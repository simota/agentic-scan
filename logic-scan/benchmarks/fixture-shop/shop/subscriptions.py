from datetime import timedelta


def next_renewal(current_renewal):
    return current_renewal + timedelta(days=30)
