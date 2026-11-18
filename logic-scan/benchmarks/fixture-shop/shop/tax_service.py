import json
import urllib.request

TAX_API = "https://tax.internal.example/rates"


def tax_rate_for(region):
    try:
        with urllib.request.urlopen(f"{TAX_API}/{region}", timeout=2) as response:
            return float(json.load(response)["rate"])
    except Exception:
        return 0.0
