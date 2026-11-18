from shop.config import REGION_SURCHARGE, STANDARD_SHIPPING_FEE

FREE_SHIPPING_THRESHOLD = 3000

SUPPORTED_CARRIERS = ("yamato", "sagawa", "japan-post")


def carrier_supported(carrier):
    return carrier in SUPPORTED_CARRIERS


def region_surcharge(region):
    return REGION_SURCHARGE.get(region, 0)


def surcharge_regions():
    return sorted(REGION_SURCHARGE)


def shipping_fee(order, net_amount):
    if order.get("staff_shipping_fee"):
        return order["staff_shipping_fee"] + region_surcharge(order["region"])
    if net_amount >= FREE_SHIPPING_THRESHOLD:
        return region_surcharge(order["region"])
    return STANDARD_SHIPPING_FEE + region_surcharge(order["region"])
