import csv
import io


def parse_amount(text):
    return float(text.replace(",", ""))


def read_price_list(raw):
    rows = csv.DictReader(io.StringIO(raw), delimiter=";")
    return {row["sku"]: parse_amount(row["price"]) for row in rows}
