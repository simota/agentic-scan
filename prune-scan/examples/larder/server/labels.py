"""Thermal shelf labels (ZPL) for barcode printers."""
from server.store import backend


def zpl_label(item_id):
    (name,) = backend().query("SELECT name FROM items WHERE id = ?", (item_id,))[0]
    return f"^XA^FO50,50^A0N,40,40^FD{name}^FS^BY2^FO50,110^BCN,80^FD{item_id:08d}^FS^XZ"
