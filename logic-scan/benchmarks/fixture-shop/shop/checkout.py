from shop.coupons import apply_coupon
from shop.pricing import order_net
from shop.shipping import shipping_fee
from shop.tax_service import tax_rate_for


def charge_amount(order, user, coupon=None):
    net = order_net(order["lines"])
    if coupon is not None:
        net = apply_coupon(coupon, user, net)
    rate = tax_rate_for(order["region"])
    tax = round(net * rate)
    order["shipping_fee"] = shipping_fee(order, net)
    return net + tax + order["shipping_fee"]


def earned_points(net, member):
    rate = member.get("point_rate_percent", 1)
    return int(net * rate)
