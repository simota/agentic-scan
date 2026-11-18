from datetime import datetime
from zoneinfo import ZoneInfo

TOKYO = ZoneInfo("Asia/Tokyo")


def promotion_active(promotion, at=None):
    at = at or datetime.now(TOKYO)
    return promotion["starts_at"] <= at <= promotion["ends_at"]


def promotion_label(promotion):
    name = promotion.get("name") or promotion["code"]
    return name.upper()


def campaign_window_contains(campaign, at):
    return campaign["starts_at"] <= at < campaign["ends_at"]


def apply_coupon(coupon, user, net):
    if user["id"] in coupon["used_by"]:
        raise ValueError("coupon already used")
    coupon["used_by"].append(user["id"])
    return max(net - coupon["amount_off"], 0)
