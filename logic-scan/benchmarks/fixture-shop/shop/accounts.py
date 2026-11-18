class DuplicateEmail(Exception):
    pass


def register(users, email, name):
    if any(user["email"] == email for user in users):
        raise DuplicateEmail(email)
    user = {"id": len(users) + 1, "email": email, "name": name}
    users.append(user)
    return user


def find_profile(profiles, user_id):
    try:
        return profiles[user_id]
    except KeyError:
        raise LookupError(f"no profile for user {user_id}")
