from console.repo.db import query, query_one

SALES_STATUSES = ("paid", "shipped", "delivered")


def sales_orders(merchant_id):
    placeholders = ",".join("?" for _ in SALES_STATUSES)
    return query(
        f"SELECT id, amount, created_at FROM orders WHERE merchant_id = ? AND status IN ({placeholders})",
        (merchant_id, *SALES_STATUSES),
    )


def revenue(merchant_id):
    row = query_one(
        "SELECT COALESCE(SUM(o.amount), 0) AS total "
        "FROM orders o JOIN payments p ON p.order_id = o.id "
        "WHERE o.merchant_id = ?",
        (merchant_id,),
    )
    return row["total"]


def orders_in_month(merchant_id, first_day, last_day):
    return query(
        "SELECT id, amount, created_at FROM orders "
        "WHERE merchant_id = ? AND created_at BETWEEN ? AND ?",
        (merchant_id, first_day.isoformat(), last_day.isoformat()),
    )


def orders_created_between(merchant_id, start, end):
    return query(
        "SELECT id, amount FROM orders WHERE merchant_id = ? AND created_at >= ? AND created_at < ?",
        (merchant_id, start.isoformat(), end.isoformat()),
    )
