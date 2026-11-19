"""The app shell of the pages render.py writes beside the dashboard.

evidence.html and mockups.html share the dashboard's look (the bundled report
kit's dashboard CSS), an app bar and the theme toggle, and the dashboard links to
each of them from the tools in its console band. One shell keeps those pages alike.
Standard library only.
"""

import html

import report_style as style

DASHBOARD_REPORT_LINK = '<a class="button" href="report.html" data-l="cx_report_link"></a>'
THEME_JS = """
(function () {
  'use strict';
  var root = document.documentElement, THEME_KEY = 'scan-report-kit.theme';
  try {
    var saved = window.localStorage.getItem(THEME_KEY);
    if (saved === 'light' || saved === 'dark') root.dataset.theme = saved;
  } catch (e) { /* follow the OS theme */ }
  document.getElementById('theme').onclick = function () {
    var dark = root.dataset.theme ? root.dataset.theme === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
    try { window.localStorage.setItem(THEME_KEY, root.dataset.theme); } catch (e) { /* not remembered */ }
  };
})();
"""


def esc(text):
    return html.escape(str(text or ""))


def page(*, lang, title, policy, css, chrome, project, dashboard, body, script=""):
    """A complete page: the dashboard's CSS and app bar, then body inside main.

    chrome holds the dashboard's own labels (report_format.labels_for), so
    the app bar names the report link and the theme toggle exactly as the dashboard
    does; dashboard is this page's label for the link back to it.
    """
    return f"""<!doctype html>
<html lang="{esc(lang)}" class="app-shell">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{esc(policy)}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
{style.dashboard_css()}
{css}
</style>
</head>
<body>
<header class="appbar"><div class="appbar-in"><span class="brand"><span>{esc(chrome["kind"])}</span> <span class="appbar-project">{esc(project)}</span></span><div class="tools"><a class="button" href="dashboard.html">{esc(dashboard)}</a><a class="button" href="report.html">{esc(chrome["report_link"])}</a><button id="theme" type="button">{esc(chrome["theme"])}</button></div></div></header>
<main>
{body}
</main>
<script>
{THEME_JS}{script}
</script>
</body>
</html>
"""


def link_dashboard(page, links):
    """The dashboard with links to the pages in links ((href, label) pairs) after its report link.

    The band's tools (console.css .cx-tools) wrap at a phone's width on their own,
    so the dashboard needs no extra rule and sticky offsets stay at the band's 0.
    """
    if not links:
        return page
    if page.count(DASHBOARD_REPORT_LINK) != 1:
        raise RuntimeError("dashboard template changed: cannot place the links to its companion pages")
    anchors = "".join(f'<a class="button" href="{esc(href)}">{esc(label)}</a>' for href, label in links)
    return page.replace(DASHBOARD_REPORT_LINK, DASHBOARD_REPORT_LINK + anchors, 1)
