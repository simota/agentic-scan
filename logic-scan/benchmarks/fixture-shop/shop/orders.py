from datetime import date, datetime
from zoneinfo import ZoneInfo

from shop.config import SAME_DAY_CUTOFF_HOUR

TOKYO = ZoneInfo("Asia/Tokyo")
CANCELLABLE = {"pending", "paid", "shipped"}


def cancel(order):
    if order["status"] not in CANCELLABLE:
        raise ValueError(f"cannot cancel an order that is {order['status']}")
    order["status"] = "cancelled"
    return order


def ships_same_day(paid_at):
    return paid_at.astimezone(TOKYO).hour < SAME_DAY_CUTOFF_HOUR


def order_reference(order):
    return f"ORD-{order['id']:08d}"


def orders_paid_today(orders):
    today = date.today()
    return [o for o in orders if o["paid_at"].date() == today]


def shipping_address(customer):
    return customer["addresses"][0]


def customer_display_name(customer):
    first = customer.get("first_name", "")
    last = customer.get("last_name", "")
    return f"{last} {first}".strip()


def add_lines(order, lines=[]):
    lines.extend(order.get("new_lines", []))
    order["lines"] = lines
    return order


def business_now():
    return datetime.now(TOKYO)
