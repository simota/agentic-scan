"""Lifecycle hooks, dispatched by name from app.py."""


def on_startup(app):
    app.logger.info("Larder started")
