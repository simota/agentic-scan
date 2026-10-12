"""Formatting helpers."""


def format_price(cents):
    return f"${cents / 100:.2f}"


def format_price_legacy(cents):
    # Kept for the old checkout; new_checkout is on everywhere.
    return "$" + str(round(cents / 100, 2))


def slugify(text):
    return "-".join(text.lower().split())


# def parse_price(text):
#     text = text.strip().lstrip("$")
#     if not text:
#         return 0
#     return int(float(text) * 100)
#     # raise ValueError("bad price")
