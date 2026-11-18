SMS_LIMIT = 70


def sms_body(text):
    data = text.encode("utf-8")
    if len(data) <= SMS_LIMIT:
        return text
    return data[:SMS_LIMIT].decode("utf-8", errors="ignore")


def sms_sender_id(merchant):
    sender = merchant.get("sms_sender")
    if sender is None:
        return "CONSOLE"
    return sender


def email_key(address):
    return address.strip().lower()
