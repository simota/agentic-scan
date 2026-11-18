"""Larder API server."""
from flask import Flask, jsonify, request

from server import config, hooks, items, labels, leaderboard, oauth
from server.ab_test import assign_bucket

app = Flask(__name__)
app.config.from_object(config)

for event in config.STARTUP_EVENTS:
    getattr(hooks, f"on_{event}")(app)


@app.before_request
def bucket_visitor():
    assign_bucket(request)


@app.get("/api/items")
def list_items():
    return jsonify(items.list_items())


@app.post("/api/items")
def add_item():
    return jsonify(items.add_item(request.json)), 201


@app.delete("/api/items/<int:item_id>")
def delete_item(item_id):
    items.delete_item(item_id)
    return "", 204


@app.get("/api/items/<int:item_id>/label")
def item_label(item_id):
    return labels.zpl_label(item_id), 200, {"Content-Type": "text/plain"}


@app.get("/api/leaderboard")
def household_leaderboard():
    return jsonify(leaderboard.top_households())


@app.get("/api/v1/items")
def list_items_v1():
    # Deprecated 2024-01; kept for the iOS app 2.x (docs/clients.md).
    return jsonify({"items": items.list_items()})


@app.get("/api/export/csv")
def export_csv():
    return items.export_csv(), 200, {"Content-Type": "text/csv"}


@app.get("/debug/dump")
def debug_dump():
    return jsonify({key: str(value) for key, value in app.config.items()})


@app.post("/webhooks/stripe")
def stripe_webhook():
    items.record_payment(request.json)
    return "", 204


@app.get("/auth/login")
def auth_login():
    return "", 302, {"Location": oauth.authorize_url()}


@app.get("/auth/callback")
def auth_callback():
    oauth.on_login(request.args)
    return "", 302, {"Location": "/"}
