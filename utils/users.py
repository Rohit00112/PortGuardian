import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash


db_lock = threading.Lock()


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class AuthUser(UserMixin):
    id: int
    username: str
    password_hash: str
    role: str
    email: Optional[str] = None
    theme: str = "system"
    email_notifications: bool = False
    notification_min_severity: str = "high"
    is_active_flag: bool = True

    @property
    def is_active(self) -> bool:
        return bool(self.is_active_flag)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class UserManager:
    """Persistent user/auth and preference storage."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv("TRUSTSCAN_USERS_DB", "users.db")
        self._init_database()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_database(self):
        with db_lock:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'viewer',
                        email TEXT,
                        theme TEXT NOT NULL DEFAULT 'system',
                        email_notifications BOOLEAN NOT NULL DEFAULT 0,
                        notification_min_severity TEXT NOT NULL DEFAULT 'high',
                        is_active BOOLEAN NOT NULL DEFAULT 1,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_login DATETIME
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS dashboard_preferences (
                        user_id INTEGER PRIMARY KEY,
                        widget_order TEXT,
                        widget_visibility TEXT,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS favorites (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        resource_key TEXT NOT NULL,
                        resource_type TEXT NOT NULL,
                        label TEXT NOT NULL,
                        metadata TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(user_id, resource_key),
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                    """
                )
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_favorites_user ON favorites(user_id)")
                conn.commit()

    def has_users(self) -> bool:
        with db_lock:
            with self._connect() as conn:
                row = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
                return bool(row["count"])

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "viewer",
        email: Optional[str] = None,
        theme: str = "system",
        email_notifications: bool = False,
        notification_min_severity: str = "high",
    ) -> int:
        if role not in {"admin", "viewer"}:
            raise ValueError("Invalid role")
        if notification_min_severity not in SEVERITY_ORDER:
            raise ValueError("Invalid notification severity")
        password_hash = generate_password_hash(password)
        try:
            with db_lock:
                with self._connect() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO users (
                            username, password_hash, role, email, theme,
                            email_notifications, notification_min_severity
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            username.strip(),
                            password_hash,
                            role,
                            email.strip() if email else None,
                            theme,
                            int(email_notifications),
                            notification_min_severity,
                        ),
                    )
                    user_id = cursor.lastrowid
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO dashboard_preferences (
                            user_id, widget_order, widget_visibility
                        ) VALUES (?, ?, ?)
                        """,
                        (user_id, json.dumps(self.default_widget_order()), json.dumps(self.default_widget_visibility())),
                    )
                    conn.commit()
                    return user_id
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username already exists") from exc

    def authenticate(self, username: str, password: str) -> Optional[AuthUser]:
        user = self.get_user_by_username(username)
        if not user or not user.is_active:
            return None
        if not check_password_hash(user.password_hash, password):
            return None
        self.record_login(user.id)
        return self.get_user_by_id(user.id)

    def record_login(self, user_id: int):
        with db_lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE users SET last_login = ?, updated_at = ? WHERE id = ?",
                    (datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), user_id),
                )
                conn.commit()

    def _row_to_user(self, row: sqlite3.Row) -> Optional[AuthUser]:
        if not row:
            return None
        return AuthUser(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            role=row["role"],
            email=row["email"],
            theme=row["theme"],
            email_notifications=bool(row["email_notifications"]),
            notification_min_severity=row["notification_min_severity"],
            is_active_flag=bool(row["is_active"]),
        )

    def get_user_by_id(self, user_id: int) -> Optional[AuthUser]:
        with db_lock:
            with self._connect() as conn:
                row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                return self._row_to_user(row)

    def get_user_by_username(self, username: str) -> Optional[AuthUser]:
        with db_lock:
            with self._connect() as conn:
                row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
                return self._row_to_user(row)

    def list_users(self) -> List[Dict[str, Any]]:
        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, username, role, email, theme, email_notifications,
                           notification_min_severity, is_active, created_at, last_login
                    FROM users
                    ORDER BY username
                    """
                ).fetchall()
        return [dict(row) for row in rows]

    def update_user(
        self,
        user_id: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
        role: Optional[str] = None,
        email: Optional[str] = None,
        is_active: Optional[bool] = None,
        email_notifications: Optional[bool] = None,
        notification_min_severity: Optional[str] = None,
        theme: Optional[str] = None,
    ) -> bool:
        updates = []
        values: List[Any] = []
        if username is not None:
            updates.append("username = ?")
            values.append(username.strip())
        if password:
            updates.append("password_hash = ?")
            values.append(generate_password_hash(password))
        if role is not None:
            if role not in {"admin", "viewer"}:
                raise ValueError("Invalid role")
            updates.append("role = ?")
            values.append(role)
        if email is not None:
            updates.append("email = ?")
            values.append(email.strip() or None)
        if is_active is not None:
            updates.append("is_active = ?")
            values.append(int(is_active))
        if email_notifications is not None:
            updates.append("email_notifications = ?")
            values.append(int(email_notifications))
        if notification_min_severity is not None:
            if notification_min_severity not in SEVERITY_ORDER:
                raise ValueError("Invalid notification severity")
            updates.append("notification_min_severity = ?")
            values.append(notification_min_severity)
        if theme is not None:
            updates.append("theme = ?")
            values.append(theme)
        if not updates:
            return False
        updates.append("updated_at = ?")
        values.append(datetime.utcnow().isoformat())
        values.append(user_id)
        try:
            with db_lock:
                with self._connect() as conn:
                    cursor = conn.execute(
                        f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
                        tuple(values),
                    )
                    conn.commit()
                    return cursor.rowcount > 0
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username already exists") from exc

    def set_theme(self, user_id: int, theme: str) -> bool:
        return self.update_user(user_id, theme=theme)

    def set_notification_preferences(
        self,
        user_id: int,
        email_notifications: bool,
        notification_min_severity: str,
        email: Optional[str] = None,
    ) -> bool:
        return self.update_user(
            user_id,
            email_notifications=email_notifications,
            notification_min_severity=notification_min_severity,
            email=email,
        )

    def default_widget_order(self) -> List[str]:
        return [
            "system-health",
            "services",
            "security",
            "ports",
            "favorites",
            "notifications",
            "audit",
        ]

    def default_widget_visibility(self) -> Dict[str, bool]:
        return {
            "system-health": True,
            "services": True,
            "security": True,
            "ports": True,
            "favorites": True,
            "notifications": True,
            "audit": True,
        }

    def get_dashboard_preferences(self, user_id: int) -> Dict[str, Any]:
        default_order = self.default_widget_order()
        default_visibility = self.default_widget_visibility()
        with db_lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT widget_order, widget_visibility FROM dashboard_preferences WHERE user_id = ?",
                    (user_id,),
                ).fetchone()
                if not row:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO dashboard_preferences (
                            user_id, widget_order, widget_visibility
                        ) VALUES (?, ?, ?)
                        """,
                        (user_id, json.dumps(default_order), json.dumps(default_visibility)),
                    )
                    conn.commit()
                    return {"widget_order": default_order, "widget_visibility": default_visibility}
        return {
            "widget_order": json.loads(row["widget_order"]) if row["widget_order"] else default_order,
            "widget_visibility": json.loads(row["widget_visibility"]) if row["widget_visibility"] else default_visibility,
        }

    def save_dashboard_preferences(
        self,
        user_id: int,
        widget_order: Optional[List[str]] = None,
        widget_visibility: Optional[Dict[str, bool]] = None,
    ) -> Dict[str, Any]:
        current = self.get_dashboard_preferences(user_id)
        new_order = widget_order or current["widget_order"]
        new_visibility = widget_visibility or current["widget_visibility"]
        with db_lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO dashboard_preferences (user_id, widget_order, widget_visibility, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        widget_order = excluded.widget_order,
                        widget_visibility = excluded.widget_visibility,
                        updated_at = excluded.updated_at
                    """,
                    (
                        user_id,
                        json.dumps(new_order),
                        json.dumps(new_visibility),
                        datetime.utcnow().isoformat(),
                    ),
                )
                conn.commit()
        return {"widget_order": new_order, "widget_visibility": new_visibility}

    def get_favorites(self, user_id: int) -> List[Dict[str, Any]]:
        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, resource_key, resource_type, label, metadata, created_at
                    FROM favorites
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                    """,
                    (user_id,),
                ).fetchall()
        favorites = []
        for row in rows:
            favorite = dict(row)
            favorite["metadata"] = json.loads(favorite["metadata"]) if favorite["metadata"] else {}
            favorites.append(favorite)
        return favorites

    def add_favorite(
        self,
        user_id: int,
        resource_key: str,
        resource_type: str,
        label: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with db_lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO favorites (user_id, resource_key, resource_type, label, metadata)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(user_id, resource_key) DO UPDATE SET
                        resource_type = excluded.resource_type,
                        label = excluded.label,
                        metadata = excluded.metadata
                    """,
                    (
                        user_id,
                        resource_key,
                        resource_type,
                        label,
                        json.dumps(metadata or {}),
                    ),
                )
                conn.commit()
        return {
            "resource_key": resource_key,
            "resource_type": resource_type,
            "label": label,
            "metadata": metadata or {},
        }

    def remove_favorite(self, user_id: int, resource_key: str) -> bool:
        with db_lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM favorites WHERE user_id = ? AND resource_key = ?",
                    (user_id, resource_key),
                )
                conn.commit()
                return cursor.rowcount > 0

    def get_email_recipients_for_severity(self, severity: str) -> List[Dict[str, Any]]:
        target_rank = SEVERITY_ORDER.get(severity, 0)
        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, username, email, notification_min_severity
                    FROM users
                    WHERE is_active = 1
                      AND email_notifications = 1
                      AND email IS NOT NULL
                      AND email != ''
                    """
                ).fetchall()
        recipients = []
        for row in rows:
            user_rank = SEVERITY_ORDER.get(row["notification_min_severity"], 3)
            if target_rank >= user_rank:
                recipients.append(dict(row))
        return recipients


user_manager = UserManager()
