"""Price A/B test. Experiment ended 2025-03-31; variant A won."""
import random

from server.store import backend


def assign_bucket(req):
    if "bucket" not in req.cookies:
        backend().query("INSERT INTO experiment_assignments (visitor, bucket) VALUES (?, ?)",
                        (req.remote_addr, random.choice(["a", "b"])))
