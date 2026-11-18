"""Pantry items."""
import csv
import io

from server import config, flags, notify
from server.store import backend
from server.utils import format_price


def list_items():
    rows = backend().query("SELECT id, name, price_cents FROM items LIMIT ?", (config.PAGE_SIZE,))
    return [_row(r) for r in rows]


def _row(r):
    if flags.is_enabled("new_checkout"):
        return {"id": r[0], "name": r[1], "price_cents": r[2], "price": format_price(r[2])}
    return {"id": r[0], "name": r[1], "price_cents": r[2], "price": r[2] / 100}


def add_item(data):
    backend().query("INSERT INTO items (name, price_cents) VALUES (?, ?)", (data["name"], data["price_cents"]))
    notify.send("item_added", data["name"])
    return {"ok": True}


def delete_item(item_id):
    backend().query("DELETE FROM items WHERE id = ?", (item_id,))


def export_csv():
    out = io.StringIO()
    writer = csv.writer(out)
    for item in list_items():
        writer.writerow([item["id"], item["name"], item["price"]])
    return out.getvalue()


def record_payment(event):
    backend().query("INSERT INTO payments (stripe_id, amount) VALUES (?, ?)", (event["id"], event["amount"]))
