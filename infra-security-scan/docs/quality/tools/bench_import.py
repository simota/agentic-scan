"""Usage: bench_import.py SCRIPTS_DIR. Median wall time of importing each script module in a fresh interpreter (21 runs)."""
import statistics, subprocess, sys, time
S = sys.argv[1]
for mod in ("findings", "contract_check", "render"):
    xs = []
    for _ in range(21):
        t = time.perf_counter()
        subprocess.run([sys.executable, "-c", f"import {mod}, sys; assert 1"], cwd=S, check=True)
        xs.append((time.perf_counter() - t) * 1000)
    loads = subprocess.run([sys.executable, "-c", f"import {mod}, sys; print('iac_scan' in sys.modules)"], cwd=S,
                           capture_output=True, text=True).stdout.strip()
    print(f"{mod:15s} median {statistics.median(xs):6.1f} ms  p90 {sorted(xs)[18]:6.1f} ms  loads iac_scan={loads}")
