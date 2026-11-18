from shop.pricing import line_net, line_tax


def build_invoice(order):
    rows = []
    for line in order["lines"]:
        net = line_net(line["unit_price"], line["qty"])
        tax = line_tax(net)
        rows.append({"sku": line["sku"], "net": net, "tax": tax, "total": net + tax})
    subtotal = sum(row["net"] for row in rows)
    tax_total = sum(row["tax"] for row in rows)
    return {
        "rows": rows,
        "subtotal": subtotal,
        "tax": tax_total,
        "shipping": order["shipping_fee"],
        "total": subtotal + tax_total + order["shipping_fee"],
    }
