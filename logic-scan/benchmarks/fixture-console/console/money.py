from decimal import Decimal, ROUND_DOWN

TAX_RATE = Decimal("0.10")
PARTNER_DISCOUNT = Decimal("0.10")


def tax_on(amount):
    return int((Decimal(amount) * TAX_RATE).quantize(Decimal("1"), rounding=ROUND_DOWN))


def with_tax(amount):
    return amount + tax_on(amount)


def partner_price(amount):
    gross = with_tax(amount)
    return int((Decimal(gross) * (1 - PARTNER_DISCOUNT)).quantize(Decimal("1"), rounding=ROUND_DOWN))
