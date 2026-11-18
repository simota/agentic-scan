"""Google sign-in."""
from urllib.parse import urlencode

from server.store import backend

SCOPES = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/calendar",
]


def authorize_url():
    query = urlencode({"scope": " ".join(SCOPES), "response_type": "code"})
    return f"https://accounts.google.com/o/oauth2/v2/auth?{query}"


def on_login(profile):
    backend().query("INSERT INTO users (email) VALUES (?)", (profile["email"],))
