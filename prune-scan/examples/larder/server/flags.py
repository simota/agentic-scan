"""Server-side feature flags."""

FLAGS = {
    "new_checkout": True,
}


def is_enabled(name):
    return FLAGS.get(name, False)
