from decimal import Decimal, ROUND_DOWN

from shop.config import BULK_DISCOUNT_MIN_QTY, BULK_DISCOUNT_RATE, TAX_RATE


def validate_quantity(qty):
    if qty <= 0:
        raise ValueError("quantity must be at least 1")
    return qty


def line_net(unit_price, qty):
    validate_quantity(qty)
    net = Decimal(unit_price) * qty
    if qty > BULK_DISCOUNT_MIN_QTY:
        discount = (net * BULK_DISCOUNT_RATE).quantize(Decimal("1"), rounding=ROUND_DOWN)
        net -= discount
    return int(net)


def line_tax(net):
    return int((Decimal(net) * TAX_RATE).quantize(Decimal("1"), rounding=ROUND_DOWN))


def order_net(lines):
    return sum(line_net(line["unit_price"], line["qty"]) for line in lines)
