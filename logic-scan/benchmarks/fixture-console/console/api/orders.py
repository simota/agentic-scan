from console import states
from console.services.dashboard import average_order_value


def order_view(order):
    return {"id": order["id"], "status": states.label(order["status"]), "amount": order["amount"]}


def badge(status):
    if status == states.PENDING:
        return "warning"
    if status in (states.CANCELLED, states.REFUNDED):
        return "muted"
    return "success"


def dashboard_view(merchant_id):
    return {"average_order_value": average_order_value(merchant_id)}
