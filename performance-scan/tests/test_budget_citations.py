"""The budget ledger's "cited by" column: one pass over the findings must name
exactly the findings the per-budget rule names, in finding order."""
import random
import re
import unittest

from support import render


def cited_per_budget(budget_id, findings):
    """The ledger's rule, applied one budget at a time (the previous implementation)."""
    mention = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(budget_id)}(?![A-Za-z0-9_-])")
    return [f["id"] for f in findings if not render.is_excluded(f) and (
        f.get("budget") == budget_id or mention.search(f["impact"]))]


def finding(fid, impact, verdict="Valid", **extra):
    return {"id": fid, "impact": impact, "validation": {"verdict": verdict}, **extra}


class BudgetCitations(unittest.TestCase):
    def assert_same_as_per_budget(self, budget_ids, findings):
        citations = render.budget_citations(findings)
        for budget_id in budget_ids:
            with self.subTest(budget=budget_id):
                self.assertEqual(citations.get(budget_id, []),
                                 cited_per_budget(budget_id, findings))

    def test_boundaries_order_and_exclusions(self):
        findings = [
            finding("P-001", "B-02 and B-001 and B-01", budget="B-03"),
            finding("P-002", "予算B-02を超過し、B-01も; AB-03 B-03a B-03_x B-03-y"),
            finding("P-003", "B-01B-02 xB-01 B-01", verdict="FalsePositive", budget="B-02"),
            finding("P-004", "no mention", budget="B-01"),
            finding("P-005", "B-010 B-1 b-01 B-01.", budget=" B-02"),
            finding("P-006", "B-02 twice B-02", budget="B-02", verdict="NotApplicable"),
            finding("P-007", "B-02 twice B-02", budget="B-02"),
        ]
        self.assert_same_as_per_budget(["B-01", "B-02", "B-03", "B-001", "B-010"], findings)
        citations = render.budget_citations(findings)
        self.assertEqual(citations["B-01"], ["P-001", "P-002", "P-004", "P-005"])
        self.assertEqual(citations["B-02"], ["P-001", "P-002", "P-007"])

    def test_random_records_match_the_per_budget_rule(self):
        rng = random.Random(20261103)
        alphabet = ["B-", "B-0", "B-01", "B-1", "B-10", "0", "1", "2", "a", "_", "-", " ",
                    "予算", ".", ",", "B", "\n", "B-001", "B-02"]
        budget_ids = [f"B-{n:02d}" for n in range(12)] + ["B-001", "B-010", "B-100"]
        for _ in range(300):
            findings = []
            for i in range(rng.randint(0, 8)):
                extra = {}
                if rng.random() < 0.4:
                    extra["budget"] = rng.choice(budget_ids + ["", " B-01", "B-1"])
                verdict = rng.choice(["Valid", "Likely", "FalsePositive", "NotApplicable"])
                impact = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 30)))
                findings.append(finding(f"P-{i + 1:03d}", impact, verdict, **extra))
            self.assert_same_as_per_budget(budget_ids, findings)

    def test_ledger_cell_uses_the_citations(self):
        labels = render.LABELS["en"]
        budget = {"id": "B-01", "statement": "s", "source": "src", "status": "violated"}
        findings = [finding("P-001", "violates B-01"), finding("P-002", "B-01", "FalsePositive")]
        self.assertEqual(render.budget_cells(budget, labels, render.budget_citations(findings))[-1],
                         "P-001")
        self.assertEqual(render.budget_cells(budget, labels, render.budget_citations([]))[-1], "—")


if __name__ == "__main__":
    unittest.main()
