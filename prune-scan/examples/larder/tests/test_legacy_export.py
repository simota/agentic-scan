from server.legacy_export import export_xml


def test_export_xml_wraps_items(monkeypatch):
    monkeypatch.setattr("server.legacy_export.list_items", lambda: [])
    assert export_xml() == "<items></items>"
