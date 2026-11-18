"""XML export for the 2023 partner feed (the partner contract ended)."""
from xml.sax.saxutils import escape

from server.items import list_items


def export_xml():
    parts = ["<items>"]
    for item in list_items():
        parts.append(f"<item id=\"{item['id']}\">{escape(item['name'])}</item>")
    parts.append("</items>")
    return "".join(parts)
