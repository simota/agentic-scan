from console.repo.orders import sales_orders


def average_order_value(merchant_id):
    orders = sales_orders(merchant_id)
    total = sum(order["amount"] for order in orders)
    return total // len(orders)


def sales_count(merchant_id):
    return len(sales_orders(merchant_id))
