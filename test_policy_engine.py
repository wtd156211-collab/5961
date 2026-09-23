import io
import json
import os
import time
import unittest

from policy_engine import Policy, contains, matches, run, split_path

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def seg(p):
    return split_path(p)


class PathMatchTest(unittest.TestCase):
    def test_single_star_matches_exactly_one_segment(self):
        pat = seg("/team/*/reports")
        self.assertTrue(matches(pat, seg("/team/ops/reports")))
        self.assertFalse(matches(pat, seg("/team/ops/2026/reports")))
        self.assertFalse(matches(pat, seg("/team/reports")))

    def test_double_star_matches_zero_or_more_segments(self):
        pat = seg("/team/docs/**")
        self.assertTrue(matches(pat, seg("/team/docs")))
        self.assertTrue(matches(pat, seg("/team/docs/a")))
        self.assertTrue(matches(pat, seg("/team/docs/a/b")))
        self.assertFalse(matches(pat, seg("/team/other")))

    def test_case_sensitive(self):
        self.assertFalse(matches(seg("/team/**"), seg("/Team/docs")))

    def test_root_path(self):
        self.assertTrue(matches(seg("/"), seg("/")))
        self.assertFalse(matches(seg("/"), seg("/a")))
        self.assertTrue(matches(seg("/**"), seg("/")))

    def test_double_star_must_be_last(self):
        with self.assertRaises(ValueError):
            Policy([{"effect": "allow", "subject": "a", "path": "/x/**/y",
                     "actions": ["read"]}], [])


class ContainsTest(unittest.TestCase):
    def test_prefix_outer(self):
        self.assertTrue(contains(seg("/team/**"), seg("/team/docs/**")))
        self.assertTrue(contains(seg("/team/**"), seg("/team/docs/x")))
        self.assertFalse(contains(seg("/team/docs/**"), seg("/team/**")))

    def test_same_length_when_no_prefix_wildcard(self):
        self.assertTrue(contains(seg("/a/b"), seg("/a/b")))
        self.assertFalse(contains(seg("/a/b"), seg("/a/b/c")))

    def test_outer_star_covers_any_inner_segment(self):
        self.assertTrue(contains(seg("/team/*"), seg("/team/ops")))
        self.assertTrue(contains(seg("/team/*"), seg("/team/*")))

    def test_inner_wildcard_only_under_outer_star(self):
        self.assertFalse(contains(seg("/team/docs"), seg("/team/*")))
        self.assertTrue(contains(seg("/team/**"), seg("/team/*/x")))
        self.assertFalse(contains(seg("/team/x/**"), seg("/team/*/x")))


def make_policy(rules, delegations=()):
    return Policy(rules, delegations)


class EvalTest(unittest.TestCase):
    def test_deny_beats_allow(self):
        p = make_policy([
            {"effect": "allow", "subject": "a", "path": "/t/**", "actions": ["read"]},
            {"effect": "deny", "subject": "a", "path": "/t/**", "actions": ["read"]},
        ])
        self.assertEqual(p.evaluate("a", "/t/x", "read"), ("deny", "rule:2"))

    def test_more_specific_allow_does_not_override_deny(self):
        p = make_policy([
            {"effect": "deny", "subject": "a", "path": "/t/**", "actions": ["read"]},
            {"effect": "allow", "subject": "a", "path": "/t/docs/x", "actions": ["read"]},
        ])
        self.assertEqual(p.evaluate("a", "/t/docs/x", "read"), ("deny", "rule:1"))

    def test_specificity_by_chars_then_segments_then_index(self):
        p = make_policy([
            {"effect": "allow", "subject": "a", "path": "/t/**", "actions": ["read"]},
            {"effect": "allow", "subject": "a", "path": "/t/docs/**", "actions": ["read"]},
            {"effect": "allow", "subject": "a", "path": "/t/docs/x", "actions": ["read"]},
        ])
        self.assertEqual(p.evaluate("a", "/t/docs/x", "read"), ("allow", "rule:3"))
        self.assertEqual(p.evaluate("a", "/t/docs/y", "read"), ("allow", "rule:2"))
        self.assertEqual(p.evaluate("a", "/t/other", "read"), ("allow", "rule:1"))

    def test_segment_count_breaks_char_tie(self):
        # 非通配字符数相同（都是 "ab"），段数多者胜
        p = make_policy([
            {"effect": "allow", "subject": "a", "path": "/ab/*", "actions": ["read"]},
            {"effect": "allow", "subject": "a", "path": "/a/b", "actions": ["read"]},
        ])
        self.assertEqual(p.evaluate("a", "/a/b", "read"), ("allow", "rule:2"))

    def test_smaller_index_wins_tie(self):
        p = make_policy([
            {"effect": "allow", "subject": "a", "path": "/t/x", "actions": ["read"]},
            {"effect": "allow", "subject": "a", "path": "/t/x", "actions": ["read"]},
        ])
        self.assertEqual(p.evaluate("a", "/t/x", "read"), ("allow", "rule:1"))

    def test_no_rule_means_deny(self):
        p = make_policy([
            {"effect": "allow", "subject": "a", "path": "/t/**", "actions": ["read"]},
        ])
        self.assertEqual(p.evaluate("a", "/t/x", "write"), ("deny", "no-rule"))
        self.assertEqual(p.evaluate("b", "/t/x", "read"), ("deny", "no-rule"))
        self.assertEqual(p.evaluate("a", "/other", "read"), ("deny", "no-rule"))

    def test_empty_policy_denies_everything(self):
        p = make_policy([])
        self.assertEqual(p.evaluate("anyone", "/anything", "read"), ("deny", "no-rule"))

    def test_action_must_be_listed(self):
        p = make_policy([
            {"effect": "allow", "subject": "a", "path": "/t/**", "actions": ["read"]},
        ])
        self.assertEqual(p.evaluate("a", "/t/x", "write"), ("deny", "no-rule"))


class DelegationTest(unittest.TestCase):
    RULES = [
        {"effect": "allow", "subject": "alice", "path": "/team/**",
         "actions": ["read", "write"]},
        {"effect": "deny", "subject": "alice", "path": "/team/secret/**",
         "actions": ["read"]},
    ]

    def test_narrowing_delegation_works(self):
        p = make_policy(self.RULES, [
            {"from": "alice", "to": "bob", "path": "/team/docs/**", "actions": ["read"]},
        ])
        self.assertEqual(p.invalid_delegations, [])
        self.assertEqual(p.evaluate("bob", "/team/docs/x", "read"), ("allow", "rule:1"))
        # 委托范围之外仍然 no-rule
        self.assertEqual(p.evaluate("bob", "/team/other", "read"), ("deny", "no-rule"))
        # 委托没给的动作不生效
        self.assertEqual(p.evaluate("bob", "/team/docs/x", "write"), ("deny", "no-rule"))

    def test_widening_delegation_is_invalid(self):
        p = make_policy(self.RULES, [
            {"from": "alice", "to": "bob", "path": "/team/docs/**", "actions": ["read"]},
            {"from": "bob", "to": "carol", "path": "/team/**", "actions": ["read"]},
        ])
        self.assertEqual(p.invalid_delegations, [2])
        self.assertEqual(p.evaluate("carol", "/team/docs/x", "read"), ("deny", "no-rule"))

    def test_widening_actions_is_invalid(self):
        p = make_policy(self.RULES, [
            {"from": "alice", "to": "bob", "path": "/team/docs/**",
             "actions": ["read", "write", "delete"]},
        ])
        self.assertEqual(p.invalid_delegations, [1])

    def test_multi_hop_chain_narrows_each_hop(self):
        p = make_policy(self.RULES, [
            {"from": "alice", "to": "bob", "path": "/team/docs/**", "actions": ["read"]},
            {"from": "bob", "to": "carol", "path": "/team/docs/pub/**", "actions": ["read"]},
        ])
        self.assertEqual(p.invalid_delegations, [])
        self.assertEqual(p.evaluate("carol", "/team/docs/pub/x", "read"),
                         ("allow", "rule:1"))
        self.assertEqual(p.evaluate("carol", "/team/docs/other", "read"),
                         ("deny", "no-rule"))

    def test_invalid_delegation_cannot_be_forwarded(self):
        p = make_policy(self.RULES, [
            {"from": "alice", "to": "bob", "path": "/elsewhere/**", "actions": ["read"]},
            {"from": "bob", "to": "carol", "path": "/elsewhere/x/**", "actions": ["read"]},
        ])
        self.assertEqual(p.invalid_delegations, [1, 2])

    def test_source_deny_applies_within_delegated_scope(self):
        p = make_policy(self.RULES, [
            {"from": "alice", "to": "bob", "path": "/team/**", "actions": ["read"]},
        ])
        self.assertEqual(p.evaluate("bob", "/team/secret/x", "read"), ("deny", "rule:2"))

    def test_delegation_validated_in_declaration_order(self):
        # 第二跳在第一跳之前声明：校验时第一跳还没生效，第二跳非法
        p = make_policy(self.RULES, [
            {"from": "bob", "to": "carol", "path": "/team/docs/**", "actions": ["read"]},
            {"from": "alice", "to": "bob", "path": "/team/docs/**", "actions": ["read"]},
        ])
        self.assertEqual(p.invalid_delegations, [1])
        self.assertEqual(p.evaluate("carol", "/team/docs/x", "read"), ("deny", "no-rule"))
        self.assertEqual(p.evaluate("bob", "/team/docs/x", "read"), ("allow", "rule:1"))


class SamplesTest(unittest.TestCase):
    def check_sample(self, n):
        with open(os.path.join(SAMPLES, "policy-%d.json" % n)) as f:
            policy = Policy.from_file(f)
        with open(os.path.join(SAMPLES, "requests-%d.csv" % n)) as f:
            import csv
            requests = [
                (row["request_id"], row["subject"], row["path"], row["action"])
                for row in csv.DictReader(f)
            ]
        out = io.StringIO()
        run(policy, requests, out)
        with open(os.path.join(SAMPLES, "expected-%d.txt" % n)) as f:
            self.assertEqual(out.getvalue(), f.read())

    def test_sample_1(self):
        self.check_sample(1)

    def test_sample_2(self):
        self.check_sample(2)

    def test_sample_3(self):
        self.check_sample(3)

    def test_deterministic_across_runs(self):
        with open(os.path.join(SAMPLES, "policy-2.json")) as f:
            data = json.load(f)
        with open(os.path.join(SAMPLES, "requests-2.csv")) as f:
            import csv
            requests = [
                (row["request_id"], row["subject"], row["path"], row["action"])
                for row in csv.DictReader(f)
            ]
        results = []
        for _ in range(2):
            out = io.StringIO()
            run(Policy.from_dict(data), requests, out)
            results.append(out.getvalue())
        self.assertEqual(results[0], results[1])


class PerformanceTest(unittest.TestCase):
    def test_300k_evaluations_under_one_second(self):
        rules = []
        for s in range(500):
            subject = "svc-%d" % s
            rules.append({"effect": "allow", "subject": subject,
                          "path": "/teams/t%d/**" % (s % 50),
                          "actions": ["read", "write", "list"]})
            rules.append({"effect": "deny", "subject": subject,
                          "path": "/teams/t%d/secret/**" % (s % 50),
                          "actions": ["read"]})
            rules.append({"effect": "allow", "subject": subject,
                          "path": "/teams/*/unit-%d/reports" % (s % 20),
                          "actions": ["read"]})
        delegations = [
            {"from": "svc-%d" % s, "to": "svc-%d" % (s + 1),
             "path": "/teams/t%d/u/**" % (s % 50), "actions": ["read"]}
            for s in range(0, 499, 7)
        ]
        policy = Policy(rules, delegations)
        requests = [
            ("svc-%d" % (i % 500),
             "/teams/t%d/unit-%d/file-%d" % (i % 50, i % 100, i),
             ("read", "write", "list")[i % 3])
            for i in range(300_000)
        ]
        start = time.perf_counter()
        for subject, path, action in requests:
            policy.evaluate(subject, path, action)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 1.0,
                        "300k 次判定耗时 %.3fs，超过 1s" % elapsed)


if __name__ == "__main__":
    unittest.main()
