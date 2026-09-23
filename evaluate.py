"""命令行入口：evaluate.py <policy.json> <requests.csv>

先按委托顺序输出非法委托，再按请求顺序输出判定，行尾 LF：
    invalid-delegation,<委托下标>,too-broad
    <请求编号>,<allow|deny>,<reason>
"""

import csv
import json
import sys

from policy_eval import Policy


def run(policy_path, requests_path, out):
    with open(policy_path, "r", encoding="utf-8") as fh:
        policy = Policy.from_dict(json.load(fh))
    lines = []
    for index in policy.invalid_delegations:
        lines.append("invalid-delegation,%d,too-broad" % index)
    with open(requests_path, "r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            decision = policy.evaluate(row["subject"], row["path"], row["action"])
            lines.append("%s,%s,%s" % (row["request_id"], decision.effect, decision.reason))
    out.write("\n".join(lines) + "\n")


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: evaluate.py <policy.json> <requests.csv>\n")
        return 2
    run(argv[1], argv[2], sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
