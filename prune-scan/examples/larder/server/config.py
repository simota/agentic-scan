"""Settings read from the environment."""
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "larder.db")
SECRET_KEY = os.environ["SECRET_KEY"]
MAILCHIMP_API_KEY = os.getenv("MAILCHIMP_API_KEY")
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "50"))
STARTUP_EVENTS = ("startup",)
