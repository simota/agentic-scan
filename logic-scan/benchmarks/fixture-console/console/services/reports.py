import calendar
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from console.repo.orders import orders_created_between, orders_in_month
from console.repo.rates import latest_rate

TOKYO = ZoneInfo("Asia/Tokyo")


def monthly_orders(merchant_id, year, month):
    first_day = date(year, month, 1)
    last_day = date(year, month, calendar.monthrange(year, month)[1])
    return orders_in_month(merchant_id, first_day, last_day)


def weekly_orders(merchant_id, monday):
    start = datetime.combine(monday, datetime.min.time(), TOKYO)
    return orders_created_between(merchant_id, start, start + timedelta(days=7))


def converted_total(orders, currency):
    rate = latest_rate(currency)
    return sum(order["amount"] for order in orders) * rate


def survey_summary(answers):
    counts = {"yes": 0, "no": 0, "unanswered": 0}
    for answer in answers:
        if answer is None:
            counts["unanswered"] += 1
        elif answer:
            counts["yes"] += 1
        else:
            counts["no"] += 1
    return counts


def nps_breakdown(responses):
    counts = {"yes": 0, "no": 0, "unanswered": 0}
    for response in responses:
        key = "yes" if bool(response.get("recommend")) else "no"
        counts[key] += 1
    return counts


def single_day_promotion(promotion):
    return promotion["start_date"] is promotion["end_date"]
