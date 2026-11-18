from console.services.pricing import price_for

_carts = {}
MAX_QTY = 100


def check_quantity(qty):
    if not 1 <= qty <= MAX_QTY:
        raise ValueError("quantity out of range")
    return qty


def add_to_cart(session_merchant_id, sku, qty, unit_amount):
    check_quantity(qty)
    cart = _carts.setdefault("current", [])
    cart.append({"sku": sku, "qty": qty, "amount": price_for(session_merchant_id, unit_amount * qty)})
    return cart


def checkout(session_merchant_id):
    cart = _carts.pop("current", [])
    return sum(line["amount"] for line in cart)
