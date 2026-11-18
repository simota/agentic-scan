import pytest

from server import items


def test_row_formats_price():
    assert items._row((1, "Rice", 250))["price"] == "$2.50"


@pytest.mark.skip(reason="flaky since 2024-02")
def test_delete_item():
    items.delete_item(1)
