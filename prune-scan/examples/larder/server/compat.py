"""Compatibility shims for the 0.x client. Remove after 2025-06-30."""
from server.items import list_items


def get_items_v0(*args, **kwargs):
    return list_items(*args, **kwargs)
