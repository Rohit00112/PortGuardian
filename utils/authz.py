from functools import wraps

from flask import abort, jsonify, request
from flask_login import current_user


def role_required(*roles):
    """Require an authenticated user with one of the supplied roles."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                if request.path.startswith("/api/"):
                    return jsonify({"status": "error", "message": "Forbidden"}), 403
                abort(403)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def admin_required(func):
    return role_required("admin")(func)
