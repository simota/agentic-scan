"""Notification channels."""
import os
import smtplib
from email.message import EmailMessage

import requests


class Notifier:
    def send(self, event, text):
        raise NotImplementedError


class EmailNotifier(Notifier):
    def send(self, event, text):
        msg = EmailMessage()
        msg["Subject"] = f"Larder: {event}"
        msg.set_content(text)
        with smtplib.SMTP(os.getenv("SMTP_HOST", "localhost")) as smtp:
            smtp.send_message(msg)


class SlackNotifier(Notifier):
    def send(self, event, text):
        requests.post(os.environ["SLACK_WEBHOOK_URL"], json={"text": f"{event}: {text}"}, timeout=5)


class SmsNotifier(Notifier):
    def send(self, event, text):
        requests.post(os.environ["SMS_GATEWAY_URL"], data={"body": text}, timeout=5)


class WebhookNotifier(Notifier):
    def send(self, event, text):
        requests.post(os.environ["NOTIFY_WEBHOOK_URL"], json={"event": event, "text": text}, timeout=5)


NOTIFIERS = {"email": EmailNotifier, "slack": SlackNotifier, "sms": SmsNotifier, "webhook": WebhookNotifier}


def send(event, text):
    for channel in os.getenv("NOTIFY_CHANNELS", "email").split(","):
        NOTIFIERS[channel.strip()]().send(event, text)
