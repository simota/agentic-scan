PENDING = "pending"
PAID = "paid"
SHIPPED = "shipped"
DELIVERED = "delivered"
PARTIALLY_REFUNDED = "partially_refunded"
REFUNDED = "refunded"
CANCELLED = "cancelled"

ALL = (PENDING, PAID, SHIPPED, DELIVERED, PARTIALLY_REFUNDED, REFUNDED, CANCELLED)

LABELS = {
    PENDING: "Awaiting payment",
    PAID: "Paid",
    SHIPPED: "Shipped",
    DELIVERED: "Delivered",
    PARTIALLY_REFUNDED: "Partially refunded",
    REFUNDED: "Refunded",
    CANCELLED: "Cancelled",
}


def label(status):
    return LABELS[status]
