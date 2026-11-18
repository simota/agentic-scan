import json
from pathlib import Path

from console.money import partner_price, with_tax

TIERS = json.loads((Path(__file__).resolve().parents[2] / "config" / "tiers.json").read_text())


def merchant_tier(merchant_id):
    return TIERS.get(merchant_id, 1)


def price_for(merchant_id, amount):
    if merchant_tier(merchant_id) >= "2":
        return partner_price(amount)
    return with_tax(amount)


def free_shipping(merchant, order_total):
    return merchant["is_member"] or order_total >= 5000 and not merchant["suspended"]


def plan_fee_label(plan):
    if plan.monthly_fee == 0:
        return "Free"
    return f"{plan.monthly_fee:,} yen / month"


def shelf_price(product):
    return product["price"]
