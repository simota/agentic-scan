"""Usage: bench_run.py REPO. Median wall time of render.py on the samples (with --repo tests/fixtures) and iac_scan on tests/fixtures, 11 runs."""
import statistics, subprocess, sys, tempfile, time, os
R = sys.argv[1]; S = R + "/skills/infra-security-scan/scripts"
def bench(cmd):
    xs = []
    for _ in range(11):
        with tempfile.TemporaryDirectory() as d:
            c = [x.replace("{d}", d) for x in cmd]
            t = time.perf_counter(); subprocess.run(c, cwd=R, check=True, capture_output=True); xs.append((time.perf_counter()-t)*1000)
    return statistics.median(xs)
print("render en  %.1f ms" % bench([sys.executable, S+"/render.py", "examples/findings.sample.json", "--out", "{d}/o", "--no-pdf", "--lang", "en", "--repo", "tests/fixtures"]))
print("render ja  %.1f ms" % bench([sys.executable, S+"/render.py", "examples/findings.sample.ja.json", "--out", "{d}/o", "--no-pdf", "--lang", "ja"]))
print("iac_scan   %.1f ms" % bench([sys.executable, S+"/iac_scan.py", "tests/fixtures", "--out", "{d}/iac.json"]))
