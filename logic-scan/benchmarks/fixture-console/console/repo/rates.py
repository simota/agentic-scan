from console.repo.db import query_one


def latest_rate(currency):
    row = query_one("SELECT rate, published_at FROM rates WHERE currency = ? LIMIT 1", (currency,))
    return row["rate"] if row else None


def rate_history_head(currency):
    return query_one(
        "SELECT rate, published_at FROM rate_history WHERE currency = ? ORDER BY published_at DESC LIMIT 1",
        (currency,),
    )
