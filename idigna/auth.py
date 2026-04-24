from functools import wraps

from flask import g, redirect, session, url_for

from . import db


def role_required(*required_roles: str):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect(url_for("index"))

            user_id = session.get("user_id")
            role = session.get("role")

            if role not in required_roles:
                return redirect(url_for("index"))

            if role == "sponsor":
                g.user = db.get_sponsor_by_id(user_id)
                if not g.user:
                    session.clear()
                    return redirect(url_for("index"))

            return f(*args, **kwargs)

        return decorated

    return wrapper
