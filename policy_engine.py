"""资源授权策略求值库。

策略语义见 README.md。要点：
- 拒绝优先于允许；同效果内按具体度（非通配字符数、非通配段数、规则下标）取最优；
- 没有命中即拒绝（no-rule）；
- 委托只能收窄：逐条按声明顺序校验，非法委托不生效；
- 委托只转移 allow，deny 不参与委托。
"""

import csv
import json
import sys

ONE = "*"    # 单段通配：恰好一段
PREFIX = "**"  # 前缀通配：仅允许出现在最后一段，匹配零段或多段


def split_path(path):
    """把路径字符串切成段元组。根路径 '/' 得到空元组。"""
    if path == "/":
        return ()
    return tuple(path[1:].split("/"))


def _check_pattern(segments, where):
    for i, seg in enumerate(segments):
        if seg == PREFIX and i != len(segments) - 1:
            raise ValueError("%s: '**' 只能出现在最后一段" % where)
        if seg == "":
            raise ValueError("%s: 路径含空段（未规范化）" % where)


def _specificity(segments):
    """具体度：(非通配字符数, 非通配段数)，越大越具体。"""
    chars = 0
    segs = 0
    for seg in segments:
        if seg != ONE and seg != PREFIX:
            chars += len(seg)
            segs += 1
    return chars, segs


def matches(pattern, segments):
    """路径模式是否命中具体路径段。逐段比较，'*' 抵一段，'**' 收尾抵零段或多段。"""
    if pattern and pattern[-1] == PREFIX:
        prefix = pattern[:-1]
        if len(segments) < len(prefix):
            return False
        pattern = prefix
    elif len(pattern) != len(segments):
        return False
    for p, s in zip(pattern, segments):
        if p != ONE and p != s:
            return False
    return True


def contains(outer, inner):
    """路径包含：outer 模式覆盖的范围是否完全包住 inner 模式。

    规则（README「委托规则」第 2 条）：
    - outer 以 '**' 结尾：inner 段数不少于 outer 前缀段数，逐段比较；
    - 否则两者段数必须相同，逐段比较；
    - 逐段：outer 为 '*' 可覆盖 inner 任意一段；否则 inner 该段不许是
      通配（'*'/'**'）且两字面量必须相等。
    """
    if outer and outer[-1] == PREFIX:
        prefix = outer[:-1]
        if len(inner) < len(prefix):
            return False
        pairs = zip(prefix, inner)
    else:
        if len(inner) != len(outer):
            return False
        pairs = zip(outer, inner)
    for o, i in pairs:
        if o == ONE:
            continue
        if i == ONE or i == PREFIX:
            return False
        if o != i:
            return False
    return True


class _Entry:
    """主体索引里的一条候选：自己的规则，或沿委托链继承来的允许范围。"""

    __slots__ = ("segments", "actions", "chars", "nsegs", "rule_index", "is_deny")

    def __init__(self, segments, actions, chars, nsegs, rule_index, is_deny):
        self.segments = segments
        self.actions = actions
        self.chars = chars
        self.nsegs = nsegs
        self.rule_index = rule_index
        self.is_deny = is_deny


class _SubjectIndex:
    """单个主体的候选条目，按首段字面量分桶；首段为通配或空模式的进 wild 桶。"""

    __slots__ = ("literal", "wild")

    def __init__(self):
        self.literal = {}
        self.wild = []

    def add(self, entry):
        seg = entry.segments
        if seg and seg[0] != ONE and seg[0] != PREFIX:
            self.literal.setdefault(seg[0], []).append(entry)
        else:
            self.wild.append(entry)

    def candidates(self, segments, out):
        out.extend(self.wild)
        if segments:
            bucket = self.literal.get(segments[0])
            if bucket:
                out.extend(bucket)
        return out


class Policy:
    """已建索引的策略。构造时完成委托校验与继承展开，求值走索引与缓存。"""

    def __init__(self, rules=(), delegations=()):
        self._subjects = {}
        self._in_delegations = {}
        self._cache = {}
        self.invalid_delegations = []

        # holdings[subject] = [(segments, actions, origin_rule_index), ...]
        # 主体「实际持有」的允许范围：自己的 allow 规则 + 已判合法的委托继承。
        holdings = {}

        def subject_index(name):
            idx = self._subjects.get(name)
            if idx is None:
                idx = self._subjects[name] = _SubjectIndex()
            return idx

        parsed_rules = []
        for i, r in enumerate(rules, 1):
            segments = split_path(r["path"])
            _check_pattern(segments, "rules[%d]" % i)
            chars, nsegs = _specificity(segments)
            actions = frozenset(r["actions"])
            parsed_rules.append((i, r, segments, actions, chars, nsegs))
            entry = _Entry(segments, actions, chars, nsegs, i, r["effect"] == "deny")
            subject_index(r["subject"]).add(entry)
            if r["effect"] == "allow":
                holdings.setdefault(r["subject"], []).append(
                    (segments, actions, i)
                )

        # 逐条按声明顺序校验委托：只能收窄，非法的不生效。
        for i, d in enumerate(delegations, 1):
            segments = split_path(d["path"])
            _check_pattern(segments, "delegations[%d]" % i)
            actions = frozenset(d["actions"])
            src = holdings.get(d["from"], ())
            covering = [
                origin
                for h_seg, h_act, origin in src
                if actions <= h_act and contains(h_seg, segments)
            ]
            if not covering:
                self.invalid_delegations.append(i)
                continue
            # to 继承到的是「来源规则 ∩ 本跳范围」：求值时若请求落在本跳
            # 范围内，则来源主体的全部规则（含 deny）也参与本次收集。
            to_holdings = holdings.setdefault(d["to"], [])
            for origin in covering:
                to_holdings.append((segments, actions, origin))
            self._in_delegations.setdefault(d["to"], []).append(
                (segments, actions, d["from"])
            )

    @classmethod
    def from_dict(cls, data):
        return cls(data.get("rules", ()), data.get("delegations", ()))

    @classmethod
    def from_file(cls, fp):
        return cls.from_dict(json.load(fp))

    def evaluate(self, subject, path, action):
        """判定一次请求，返回 (decision, reason)。

        decision 为 'allow' 或 'deny'；reason 为 'rule:<下标>' 或 'no-rule'。
        """
        key = (subject, path, action)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        result = self._evaluate_uncached(subject, split_path(path), action)
        self._cache[key] = result
        return result

    def _evaluate_uncached(self, subject, segments, action):
        # 收集本人规则 + 沿有效委托链上游主体的规则中所有命中项，
        # 再统一按「拒绝优先、同效果比具体度」结算。
        best_allow = None  # ((chars, nsegs, -rule_index), rule_index)
        best_deny = None
        visited = {subject}
        stack = [subject]
        scratch = []
        while stack:
            current = stack.pop()
            idx = self._subjects.get(current)
            if idx is not None:
                del scratch[:]
                for e in idx.candidates(segments, scratch):
                    if action not in e.actions:
                        continue
                    if not matches(e.segments, segments):
                        continue
                    rank = (e.chars, e.nsegs, -e.rule_index)
                    if e.is_deny:
                        if best_deny is None or rank > best_deny[0]:
                            best_deny = (rank, e.rule_index)
                    else:
                        if best_allow is None or rank > best_allow[0]:
                            best_allow = (rank, e.rule_index)
            for d_seg, d_act, src in self._in_delegations.get(current, ()):
                if src in visited:
                    continue
                if action not in d_act:
                    continue
                if not matches(d_seg, segments):
                    continue
                visited.add(src)
                stack.append(src)
        if best_deny is not None:
            return ("deny", "rule:%d" % best_deny[1])
        if best_allow is not None:
            return ("allow", "rule:%d" % best_allow[1])
        return ("deny", "no-rule")


def run(policy, requests, out):
    """按输出格式写结果：先非法委托行，再按请求顺序写判定行。"""
    write = out.write
    for i in policy.invalid_delegations:
        write("invalid-delegation,%d,too-broad\n" % i)
    for request_id, subject, path, action in requests:
        decision, reason = policy.evaluate(subject, path, action)
        write("%s,%s,%s\n" % (request_id, decision, reason))


def read_requests(fp):
    for row in csv.DictReader(fp):
        yield row["request_id"], row["subject"], row["path"], row["action"]


def main(argv):
    with open(argv[1]) as f:
        policy = Policy.from_file(f)
    with open(argv[2]) as f:
        requests = list(read_requests(f))
    run(policy, requests, sys.stdout)


if __name__ == "__main__":
    main(sys.argv)
