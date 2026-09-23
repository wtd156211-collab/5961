"""资源授权策略求值库。

策略由 allow/deny 规则与委托（delegation）组成，判定原则：
拒绝优先于允许；同效果内越具体越优先；没有命中就是拒绝。
委托只能收窄不能放大，非法委托不生效；求值时，落在有效委托
范围内的请求会连带委托方（含更上游）的规则一起参与判定。
"""

__all__ = ["Policy", "Decision", "Pattern", "split_path", "ALLOW", "DENY"]

ALLOW = "allow"
DENY = "deny"

_ONE = "*"
_GLOB = "**"


def split_path(path):
    """把规范化路径切成段元组；根路径 '/' 为零段。"""
    if path == "/":
        return ()
    return tuple(path.split("/")[1:])


class Pattern:
    """资源路径模式。`*` 匹配恰好一段，`**` 只能收尾、匹配零段或多段。"""

    __slots__ = ("raw", "segments", "prefix", "has_globstar", "lit_chars", "lit_segs")

    def __init__(self, raw):
        self.raw = raw
        segments = split_path(raw)
        self.segments = segments
        self.has_globstar = bool(segments) and segments[-1] == _GLOB
        self.prefix = segments[:-1] if self.has_globstar else segments
        lit_chars = 0
        lit_segs = 0
        for seg in segments:
            if seg != _ONE and seg != _GLOB:
                lit_chars += len(seg)
                lit_segs += 1
        self.lit_chars = lit_chars
        self.lit_segs = lit_segs

    def matches(self, segments):
        """判断请求路径段是否命中本模式。比较区分大小写。"""
        prefix = self.prefix
        if self.has_globstar:
            if len(segments) < len(prefix):
                return False
        elif len(segments) != len(prefix):
            return False
        for pat, seg in zip(prefix, segments):
            if pat != _ONE and pat != seg:
                return False
        return True

    def covers(self, inner):
        """判断 self（outer，手里那条）是否完整覆盖 inner（要转出的）。

        outer 以 `**` 结尾时，inner 段数不得少于 outer 的前缀段数；
        否则两者段数必须相同。逐段比较：outer 的 `*` 可覆盖 inner 任意一段，
        其余位置必须字面相等；inner 的通配段只有 outer 同段为 `*` 才允许。
        outer `**` 覆盖到的剩余位置对 inner 不设限制。
        """
        outer_prefix = self.prefix
        inner_segments = inner.segments
        if self.has_globstar:
            if len(inner_segments) < len(outer_prefix):
                return False
        elif len(inner_segments) != len(outer_prefix):
            return False
        for outer_seg, inner_seg in zip(outer_prefix, inner_segments):
            if outer_seg == _ONE:
                continue
            if inner_seg == _ONE or inner_seg == _GLOB:
                return False
            if outer_seg != inner_seg:
                return False
        return True


class Decision:
    """一次判定的结果：effect 为 allow/deny，reason 为 rule:<下标> 或 no-rule。"""

    __slots__ = ("effect", "reason")

    def __init__(self, effect, reason):
        self.effect = effect
        self.reason = reason

    def __eq__(self, other):
        return (
            isinstance(other, Decision)
            and self.effect == other.effect
            and self.reason == other.reason
        )

    def __repr__(self):
        return "Decision(%r, %r)" % (self.effect, self.reason)


class _Node:
    """按路径段建立的前缀索引节点。"""

    __slots__ = ("literal", "star", "terminal", "globstar")

    def __init__(self):
        self.literal = {}
        self.star = None
        self.terminal = []
        self.globstar = []


def _insert(root, pattern, entry):
    node = root
    for seg in pattern.prefix:
        if seg == _ONE:
            child = node.star
            if child is None:
                child = node.star = _Node()
        else:
            child = node.literal.get(seg)
            if child is None:
                child = node.literal[seg] = _Node()
        node = child
    if pattern.has_globstar:
        node.globstar.append(entry)
    else:
        node.terminal.append(entry)


def _collect(root, segments, out):
    """收集命中请求路径的全部条目：沿途的 `**` 条目 + 终点上的精确条目。"""
    stack = [(root, 0)]
    depth = len(segments)
    while stack:
        node, i = stack.pop()
        if node.globstar:
            out.extend(node.globstar)
        if i == depth:
            out.extend(node.terminal)
            continue
        seg = segments[i]
        child = node.literal.get(seg)
        if child is not None:
            stack.append((child, i + 1))
        if node.star is not None:
            stack.append((node.star, i + 1))
    return out


class Policy:
    """加载策略、校验委托链、按主体建索引并求值。"""

    def __init__(self, rules=(), delegations=()):
        self._tries = {}
        held = {}
        for index, rule in enumerate(rules, 1):
            pattern = Pattern(rule["path"])
            entry = (
                rule["effect"],
                frozenset(rule["actions"]),
                pattern.lit_chars,
                pattern.lit_segs,
                index,
            )
            root = self._tries.setdefault(rule["subject"], _Node())
            _insert(root, pattern, entry)
            if rule["effect"] == ALLOW:
                held.setdefault(rule["subject"], []).append(
                    (pattern, entry[1])
                )

        # 逐条按声明顺序校验委托：只算已经判定合法的委托。
        # 委托只转移允许；非法委托不生效，也不参与后续校验与求值。
        self.invalid_delegations = []
        self._incoming = {}
        for index, delegation in enumerate(delegations, 1):
            pattern = Pattern(delegation["path"])
            actions = frozenset(delegation["actions"])
            ok = False
            for held_pattern, held_actions in held.get(delegation["from"], ()):
                if actions <= held_actions and held_pattern.covers(pattern):
                    ok = True
                    break
            if not ok:
                self.invalid_delegations.append(index)
                continue
            held.setdefault(delegation["to"], []).append((pattern, actions))
            edge = (pattern, actions, delegation["from"])
            self._incoming.setdefault(delegation["to"], []).append(edge)

    @classmethod
    def from_dict(cls, data):
        return cls(data.get("rules", ()), data.get("delegations", ()))

    def _gather(self, subject, segments, action, entries):
        """收集 subject 自身及沿有效委托链上游所有主体命中请求的条目。

        只有请求落在某条委托的范围（路径 + 动作）内，该委托方的规则
        才参与本次判定；链上几跳都递归生效，用 visited 防止成环。
        """
        visited = {subject}
        stack = [subject]
        while stack:
            current = stack.pop()
            root = self._tries.get(current)
            if root is not None:
                _collect(root, segments, entries)
            for pattern, actions, source in self._incoming.get(current, ()):
                if source in visited or action not in actions:
                    continue
                if pattern.matches(segments):
                    visited.add(source)
                    stack.append(source)
        return entries

    def evaluate(self, subject, path, action):
        """对一次请求（主体、路径、动作）求值，返回 Decision。"""
        segments = split_path(path)
        entries = self._gather(subject, segments, action, [])
        best_allow = None
        best_deny = None
        allow_index = 0
        deny_index = 0
        for effect, actions, lit_chars, lit_segs, index in entries:
            if action not in actions:
                continue
            key = (lit_chars, lit_segs, -index)
            if effect == DENY:
                if best_deny is None or key > best_deny:
                    best_deny = key
                    deny_index = index
            else:
                if best_allow is None or key > best_allow:
                    best_allow = key
                    allow_index = index
        if best_deny is not None:
            return Decision(DENY, "rule:%d" % deny_index)
        if best_allow is not None:
            return Decision(ALLOW, "rule:%d" % allow_index)
        return Decision(DENY, "no-rule")
