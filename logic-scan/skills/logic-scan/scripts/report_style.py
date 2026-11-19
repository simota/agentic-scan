"""The shared visual system (docs/design.md) as strings ready to inline into a page."""

from pathlib import Path

ASSETS = Path(__file__).resolve().parent / "report_assets"


def _asset(name):
    return (ASSETS / name).read_text(encoding="utf-8")


def dashboard_css():
    """Stylesheet for the interactive dashboard (light and dark themes)."""
    return _asset("dashboard.css")


def console_css():
    """console-triage layer (band, tiles, lanes, inspector); inlined after the page's own stylesheet."""
    return _asset("console.css")


def console_js():
    """console-triage renderer: defines window.AgenticConsole; contains no script end tag."""
    text = _asset("console.js")
    if "</" in text:
        raise ValueError("console.js must not contain '</' when inlined into a script element")
    return text
