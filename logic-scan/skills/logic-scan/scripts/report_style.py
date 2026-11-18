"""The shared visual system (docs/design.md) as strings ready to inline into a page."""

from pathlib import Path

ASSETS = Path(__file__).resolve().parent / "report_assets"


def _asset(name):
    return (ASSETS / name).read_text(encoding="utf-8")


def dashboard_css():
    """Stylesheet for the interactive dashboard (light and dark themes)."""
    return _asset("dashboard.css")
