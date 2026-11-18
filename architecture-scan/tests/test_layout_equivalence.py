"""The diagram layout and label placement keep their output while running faster.

`findings.py check` compares bytes with a fresh render, so a faster layout must
place every node, route and label exactly where the earlier one did. The
digests below were taken from the layout before it counted crossings with a
pair table and before label placement skipped boxes that overlap nothing.
"""
import hashlib
import random
import unittest

from test_architecture_scan import findings, render


def graph(n, e, seed):
    rr = random.Random(seed)
    nodes = [{"id": f"m{i}", "label": f"module {i}"} for i in range(n)]
    pairs = []
    while len(pairs) < e:
        pair = tuple(rr.sample(range(n), 2))
        if pair not in pairs:
            pairs.append(pair)
    return {"nodes": nodes, "edges": [{"from": f"m{a}", "to": f"m{b}", "label": f"e{k}"}
                                      for k, (a, b) in enumerate(pairs)]}


# (nodes, edges, seed): sha256 of repr(arch_layout), sha256 of both SVGs.
GOLDEN = {
    (12, 20, 1): ("d22c8986f01342059de9b689e9bbd98bd0524ad800fd29264daafa6f00320787",
                  "0c5883fe9e347fa583c30a788d8858c3a8f41d510d021138affeb292b853426a"),
    (30, 60, 2): ("7580621ca834122840e50378915773063c332d71b67ce6f64dbbd6e54f472cc6",
                  "7d3a91d45019a0392dab93f7707692fbbc9a99522afc764044bc0f944db1d7e2"),
    # The largest diagrams the schema accepts.
    (60, 150, 3): ("69e31bfb22096fdb7cb40e2cca658603e1e634ef444b3d34434c4ddd527bfa77",
                   "6b278340527a0e8b2c633f3b0241f06190a6f89f8dfb1f269169bd90807981d9"),
}


def reference_label_spot(segments, width, taken, height=render.LABEL_H):
    """label_spot as first written: every spot scored against every box."""
    def overlap(spot):
        x, y = spot[0] - width / 2, spot[1] - height
        return sum(weight * max(0, min(x + width, bx + bw) - max(x, bx))
                   * max(0, min(y + height, by + bh) - max(y, by))
                   for bx, by, bw, bh, weight in taken)

    spots = [render.bezier(segment, t) for t in (0.5, 0.35, 0.65, 0.2, 0.8, 0.1, 0.9)
             for segment in segments]
    spot = min(spots, key=overlap)
    taken.append((spot[0] - width / 2, spot[1] - height, width, height, 1))
    return spot


class LayoutEquivalenceTests(unittest.TestCase):
    def test_layouts_and_svgs_match_the_recorded_digests(self):
        self.assertEqual(findings.MAX_NODES, 60)
        self.assertEqual(findings.MAX_EDGES, 150)
        for (n, e, seed), (layout_digest, svg_digest) in GOLDEN.items():
            with self.subTest(nodes=n, edges=e):
                arch = {"before": graph(n, e, seed), "after": graph(n, e, seed + 100)}
                layout = render.arch_layout(arch)
                changes = render.diagram_changes(arch)
                svg = "".join(render.svg_diagram(arch[side], side, changes, layout, "t")
                              for side in ("before", "after"))
                self.assertEqual(hashlib.sha256(repr(layout).encode()).hexdigest(), layout_digest)
                self.assertEqual(hashlib.sha256(svg.encode()).hexdigest(), svg_digest)

    def test_label_spot_matches_scoring_every_box(self):
        rr = random.Random(9)
        for _ in range(300):
            segments = [tuple((rr.uniform(0, 400), rr.uniform(0, 300)) for _ in range(4))
                        for _ in range(rr.randint(1, 3))]
            boxes = [(rr.choice([rr.uniform(0, 400), rr.randint(0, 400)]),
                      rr.choice([rr.uniform(0, 300), rr.randint(0, 300)]),
                      rr.randint(10, 184), rr.randint(14, 44), rr.choice([1, 10]))
                     for _ in range(rr.randint(0, 40))]
            width, height = rr.randint(6, 160), rr.choice([14, 28, 42])
            fast, slow = list(boxes), list(boxes)
            self.assertEqual(render.label_spot(segments, width, fast, height),
                             reference_label_spot(segments, width, slow, height))
            self.assertEqual(fast, slow)

    def test_a_crowded_spot_still_takes_the_least_overlap(self):
        # Every spot overlaps something, so no early stop applies.
        segment = ((0, 50), (50, 50), (150, 50), (200, 50))
        taken = [(-50, 0, 300, 100, 1), (60, 30, 40, 30, 10)]
        self.assertEqual(render.label_spot([segment], 40, list(taken)),
                         reference_label_spot([segment], 40, list(taken)))


if __name__ == "__main__":
    unittest.main()
