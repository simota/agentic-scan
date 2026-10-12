"""Weekly leaderboard of households by food saved."""
from server.store import backend


def top_households(limit=10):
    rows = backend().query(
        "SELECT household, COUNT(*) AS saved FROM items GROUP BY household ORDER BY saved DESC LIMIT ?", (limit,))
    return [{"household": r[0], "saved": r[1]} for r in rows]
