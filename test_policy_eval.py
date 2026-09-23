import io
import json
import os
import time
import unittest

from policy_eval import ALLOW, DENY, Pattern, Policy, split_path
from evaluate import run

SAMPLES = os.path.join(os.path.dirname(__file__), "samples")


def make_policy(rules, delegations=()):
    return Policy.from_dict({"rules": rules, "delegations": delegations})


def allow(subject, path, actions):
    return {"effect": "allow", "subject": subject, "path": path, "actions": actions}


def deny(subject, path, actions):
    return {"effect": "deny", "subject": subject, "path": path, "actions": actions}


class PatternTest(unittest.TestCase):
    def test_split_root(self):
        self.assertEqual(split_path("/"), ())
        self.assertEqual(split_path("/a/b"), ("a", "b"))

    def test_star_matches_exactly_one_segment(self):
        pattern = Pattern("/team/*/reports")
        self.assertTrue(pattern.matches(("team", "ops", "reports")))
        self.assertFalse(pattern.matches(("team", "ops", "2026", "reports")))
        self.assertFalse(pattern.matches(("team", "reports")))

    def test_globstar_matches_zero_or_more_segments(self):
        pattern = Pattern("/team/docs/**")
        self.assertTrue(pattern.matches(("team", "docs")))
        self.assertTrue(pattern.matches(("team", "docs", "a")))
        self.assertTrue(pattern.matches(("team", "docs", "a", "b")))
        self.assertFalse(pattern.matches(("team", "other")))

    def test_matching_is_case_sensitive(self):
        pattern = Pattern("/team/docs")
        self.assertFalse(pattern.matches(("Team", "docs")))
        self.assertTrue(pattern.matches(("team", "docs")))

    def test_root_pattern(self):
        self.assertTrue(Pattern("/").matches(()))
        self.assertFalse(Pattern("/").matches(("a",)))
        self.assertTrue(Pattern("/**").matches(("a", "b")))


class EvaluateTest(unittest.TestCase):
    def test_empty_policy_denies_everything(self):
        policy = make_policy([])
        self.assertEqual(policy.evaluate("alice", "/anything", "read").reason, "no-rule")
        self.assertEqual(policy.evaluate("alice", "/", "list").effect, DENY)

    def test_no_match_is_no_rule(self):
        policy = make_policy([allow("alice", "/team/**", ["read"])])
        decision = policy.evaluate("alice", "/other", "read")
        self.assertEqual((decision.effect, decision.reason), (DENY, "no-rule"))

    def test_action_must_be_listed(self):
        policy = make_policy([allow("alice", "/team/**", ["read"])])
        self.assertEqual(policy.evaluate("alice", "/team/x", "write").reason, "no-rule")
        self.assertEqual(policy.evaluate("alice", "/team/x", "read").effect, ALLOW)

    def test_subject_is_case_sensitive(self):
        policy = make_policy([allow("Alice", "/team/**", ["read"])])
        self.assertEqual(policy.evaluate("alice", "/team/x", "read").reason, "no-rule")
        self.assertEqual(policy.evaluate("Alice", "/team/x", "read").effect, ALLOW)

    def test_deny_beats_allow(self):
        policy = make_policy([
            allow("alice", "/team/**", ["read"]),
            deny("alice", "/team/secret/**", ["read"]),
        ])
        decision = policy.evaluate("alice", "/team/secret/x", "read")
        self.assertEqual((decision.effect, decision.reason), (DENY, "rule:2"))

    def test_more_specific_allow_wins_reason(self):
        policy = make_policy([
            allow("alice", "/team/**", ["read"]),
            allow("alice", "/team/docs/**", ["read"]),
        ])
        self.assertEqual(policy.evaluate("alice", "/team/docs/x", "read").reason, "rule:2")

    def test_specificity_char_count_before_segment_count(self):
        policy = make_policy([
            allow("alice", "/aaaaaa/**", ["read"]),  # 非通配字符 6，段 1
            allow("alice", "/*/x/y", ["read"]),      # 非通配字符 2，段 2
        ])
        # 字符数优先于段数：rule:1 更具体
        self.assertEqual(policy.evaluate("alice", "/aaaaaa/x/y", "read").reason, "rule:1")

    def test_specificity_segment_count_breaks_tie(self):
        policy = make_policy([
            allow("alice", "/aaaa/*", ["read"]),     # 字符 4，段 1
            allow("alice", "/aa/bb", ["read"]),      # 字符 4，段 2
        ])
        self.assertEqual(policy.evaluate("alice", "/aa/bb", "read").reason, "rule:2")

    def test_smaller_index_breaks_tie(self):
        policy = make_policy([
            allow("alice", "/team/**", ["read"]),
            deny("alice", "/team/**", ["read"]),
            deny("alice", "/team/*", ["read"]),
        ])
        # 两条 deny 具体度相同，下标小者优先
        self.assertEqual(policy.evaluate("alice", "/team/x", "read").reason, "rule:2")


class DelegationTest(unittest.TestCase):
    def test_valid_delegation_grants_within_scope(self):
        policy = make_policy(
            [allow("alice", "/team/**", ["read", "write"])],
            [{"from": "alice", "to": "bob", "path": "/team/docs/**", "actions": ["read"]}],
        )
        self.assertEqual(policy.invalid_delegations, [])
        decision = policy.evaluate("bob", "/team/docs/x", "read")
        self.assertEqual((decision.effect, decision.reason), (ALLOW, "rule:1"))
        # 委托范围之外、动作之外都不生效
        self.assertEqual(policy.evaluate("bob", "/team/other/x", "read").reason, "no-rule")
        self.assertEqual(policy.evaluate("bob", "/team/docs/x", "write").reason, "no-rule")

    def test_too_broad_path_is_invalid(self):
        policy = make_policy(
            [allow("alice", "/team/docs/**", ["read"])],
            [{"from": "alice", "to": "bob", "path": "/team/**", "actions": ["read"]}],
        )
        self.assertEqual(policy.invalid_delegations, [1])
        self.assertEqual(policy.evaluate("bob", "/team/docs/x", "read").reason, "no-rule")

    def test_too_broad_action_is_invalid(self):
        policy = make_policy(
            [allow("alice", "/team/**", ["read"])],
            [{"from": "alice", "to": "bob", "path": "/team/**", "actions": ["read", "write"]}],
        )
        self.assertEqual(policy.invalid_delegations, [1])

    def test_inner_wildcard_needs_outer_star(self):
        policy = make_policy(
            [allow("alice", "/team/docs/**", ["read"]), allow("alice", "/team/*", ["read"])],
            [
                {"from": "alice", "to": "bob", "path": "/team/*", "actions": ["read"]},
                {"from": "alice", "to": "carol", "path": "/team/*", "actions": ["read"]},
            ],
        )
        # 委托 1：from 只有 /team/docs/**，inner 的 * 落在字面量段上，非法
        # 这里两条委托各自独立：alice 的 rule:2 /team/* 可以覆盖 /team/*
        self.assertEqual(policy.invalid_delegations, [])
        policy2 = make_policy(
            [allow("alice", "/team/docs/**", ["read"])],
            [{"from": "alice", "to": "bob", "path": "/team/*", "actions": ["read"]}],
        )
        self.assertEqual(policy2.invalid_delegations, [1])

    def test_two_hop_chain_narrows(self):
        policy = make_policy(
            [allow("alice", "/team/**", ["read"])],
            [
                {"from": "alice", "to": "bob", "path": "/team/docs/**", "actions": ["read"]},
                {"from": "bob", "to": "carol", "path": "/team/docs/public/**", "actions": ["read"]},
            ],
        )
        self.assertEqual(policy.invalid_delegations, [])
        self.assertEqual(
            policy.evaluate("carol", "/team/docs/public/x", "read").reason, "rule:1"
        )
        self.assertEqual(
            policy.evaluate("carol", "/team/docs/secret/x", "read").reason, "no-rule"
        )

    def test_invalid_delegation_cannot_be_redelegated(self):
        policy = make_policy(
            [allow("alice", "/team/docs/**", ["read"])],
            [
                {"from": "alice", "to": "bob", "path": "/team/**", "actions": ["read"]},
                {"from": "bob", "to": "carol", "path": "/team/docs/**", "actions": ["read"]},
            ],
        )
        # 第一跳非法，bob 手里没有东西，第二跳也非法
        self.assertEqual(policy.invalid_delegations, [1, 2])
        self.assertEqual(policy.evaluate("carol", "/team/docs/x", "read").reason, "no-rule")

    def test_delegation_validated_in_declaration_order(self):
        policy = make_policy(
            [allow("alice", "/team/**", ["read"])],
            [
                {"from": "bob", "to": "carol", "path": "/team/docs/**", "actions": ["read"]},
                {"from": "alice", "to": "bob", "path": "/team/**", "actions": ["read"]},
            ],
        )
        # 校验委托 1 时 bob 还没有权限，非法；委托 2 合法
        self.assertEqual(policy.invalid_delegations, [1])
        self.assertEqual(policy.evaluate("bob", "/team/x", "read").effect, ALLOW)
        self.assertEqual(policy.evaluate("carol", "/team/docs/x", "read").reason, "no-rule")

    def test_upstream_deny_applies_within_delegated_scope(self):
        policy = make_policy(
            [
                deny("alice", "/team/secret/**", ["read"]),
                allow("alice", "/team/**", ["read"]),
            ],
            [{"from": "alice", "to": "bob", "path": "/team/**", "actions": ["read"]}],
        )
        decision = policy.evaluate("bob", "/team/secret/x", "read")
        self.assertEqual((decision.effect, decision.reason), (DENY, "rule:1"))

    def test_upstream_deny_ignored_outside_delegated_scope(self):
        policy = make_policy(
            [
                deny("alice", "/team/**", ["read"]),
                allow("alice", "/team/**", ["read"]),
                allow("bob", "/public/**", ["read"]),
            ],
            [{"from": "alice", "to": "bob", "path": "/team/docs/**", "actions": ["read"]}],
        )
        # bob 自己的 /public 请求与 alice 的 deny 无关
        self.assertEqual(policy.evaluate("bob", "/public/x", "read").effect, ALLOW)

    def test_delegation_cycle_terminates(self):
        policy = make_policy(
            [allow("alice", "/team/**", ["read"]), allow("bob", "/team/**", ["read"])],
            [
                {"from": "alice", "to": "bob", "path": "/team/**", "actions": ["read"]},
                {"from": "bob", "to": "alice", "path": "/team/**", "actions": ["read"]},
            ],
        )
        self.assertEqual(policy.evaluate("alice", "/team/x", "read").effect, ALLOW)
        self.assertEqual(policy.evaluate("bob", "/team/x", "read").effect, ALLOW)


class SamplesTest(unittest.TestCase):
    def check_case(self, name):
        policy_path = os.path.join(SAMPLES, "policy-%s.json" % name)
        requests_path = os.path.join(SAMPLES, "requests-%s.csv" % name)
        expected_path = os.path.join(SAMPLES, "expected-%s.txt" % name)
        out = io.StringIO()
        run(policy_path, requests_path, out)
        with open(expected_path, "r", encoding="utf-8") as fh:
            self.assertEqual(out.getvalue(), fh.read())

    def test_case_1(self):
        self.check_case("1")

    def test_case_2(self):
        self.check_case("2")

    def test_case_3(self):
        self.check_case("3")

    def test_deterministic_output(self):
        policy_path = os.path.join(SAMPLES, "policy-2.json")
        requests_path = os.path.join(SAMPLES, "requests-2.csv")
        first = io.StringIO()
        second = io.StringIO()
        run(policy_path, requests_path, first)
        run(policy_path, requests_path, second)
        self.assertEqual(first.getvalue(), second.getvalue())


class PerformanceTest(unittest.TestCase):
    def test_300k_evaluations_under_one_second(self):
        with open(os.path.join(SAMPLES, "policy-2.json"), "r", encoding="utf-8") as fh:
            policy = Policy.from_dict(json.load(fh))
        subjects = ["svc-%s-%d" % (team, i) for team in ("alpha", "beta", "gamma") for i in range(20)]
        teams = ("alpha", "beta", "gamma", "delta", "epsilon")
        actions = ("read", "write", "list")
        requests = [
            (
                subjects[i % len(subjects)],
                "/teams/%s/unit-%d/file-%d" % (teams[i % len(teams)], i % 120, i % 10),
                actions[i % len(actions)],
            )
            for i in range(300000)
        ]
        start = time.perf_counter()
        for subject, path, action in requests:
            policy.evaluate(subject, path, action)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 1.0, "300k 次判定耗时 %.3fs" % elapsed)


if __name__ == "__main__":
    unittest.main()
