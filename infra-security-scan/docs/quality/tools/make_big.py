"""Usage: make_big.py REPO OUT.json. The English sample plus 1000 copies of F-006 (F-100..F-1099): the scale case for ui_metrics.js."""
import copy, json, sys
d = json.load(open(sys.argv[1] + "/examples/findings.sample.json"))
base = next(f for f in d["findings"] if f["id"] == "F-006")
for i in range(100, 1100):
    f = copy.deepcopy(base); f["id"] = f"F-{i}"; f.pop("attack_paths", None); f["title"] = f"{base['title']} #{i}"
    d["findings"].append(f)
json.dump(d, open(sys.argv[2], "w"))
