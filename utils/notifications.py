import hashlib
import hmac
import json
import logging
import os
import smtplib
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import Any, Callable, Dict, List, Optional

from utils.users import SEVERITY_ORDER, user_manager


logger = logging.getLogger("notifications")
db_lock = threading.RLock()


class NotificationManager:
    """Notification inbox, delivery pipeline, and port change monitor."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv("TRUSTSCAN_NOTIFICATIONS_DB", "notifications.db")
        self.running = False
        self.delivery_thread = None
        self.port_thread = None
        self.port_provider: Optional[Callable[[], List[Dict[str, Any]]]] = None
        self.retry_base_seconds = int(os.getenv("TRUSTSCAN_NOTIFICATION_RETRY_SECONDS", "5"))
        self.port_poll_interval = int(os.getenv("TRUSTSCAN_PORT_POLL_INTERVAL", "15"))
        self._last_port_snapshot: Optional[Dict[str, Dict[str, Any]]] = None
        self._init_database()
        self._seed_rules()

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
                    CREATE TABLE IF NOT EXISTS notifications (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        severity TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        source TEXT NOT NULL,
                        title TEXT NOT NULL,
                        message TEXT NOT NULL,
                        payload TEXT,
                        resource_key TEXT
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS notification_reads (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        notification_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL,
                        read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(notification_id, user_id)
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS notification_webhooks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        url TEXT NOT NULL,
                        secret TEXT,
                        min_severity TEXT NOT NULL DEFAULT 'high',
                        is_active BOOLEAN NOT NULL DEFAULT 1,
                        created_by TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS notification_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT UNIQUE NOT NULL,
                        email_enabled BOOLEAN NOT NULL DEFAULT 1,
                        webhook_enabled BOOLEAN NOT NULL DEFAULT 1,
                        min_severity TEXT NOT NULL DEFAULT 'high',
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS notification_deliveries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        notification_id INTEGER NOT NULL,
                        channel TEXT NOT NULL,
                        target TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'pending',
                        attempt_count INTEGER NOT NULL DEFAULT 0,
                        next_attempt_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_attempt_at DATETIME,
                        last_error TEXT,
                        response_code INTEGER,
                        metadata TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_status ON notification_deliveries(status, next_attempt_at)")
                conn.commit()

    def _seed_rules(self):
        default_rules = [
            ("service_event", 1, 1, "high"),
            ("schedule_failure", 1, 1, "high"),
            ("resource_limit_violation", 1, 1, "high"),
            ("security_threat", 1, 1, "medium"),
            ("port_change", 0, 1, "high"),
        ]
        with db_lock:
            with self._connect() as conn:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO notification_rules (
                        event_type, email_enabled, webhook_enabled, min_severity
                    ) VALUES (?, ?, ?, ?)
                    """,
                    default_rules,
                )
                conn.commit()

    def start(self, port_provider: Optional[Callable[[], List[Dict[str, Any]]]] = None):
        if self.running:
            return
        self.port_provider = port_provider
        self.running = True
        self.delivery_thread = threading.Thread(target=self._delivery_loop, daemon=True)
        self.delivery_thread.start()
        if port_provider:
            self.port_thread = threading.Thread(target=self._port_monitor_loop, daemon=True)
            self.port_thread.start()

    def stop(self):
        self.running = False
        if self.delivery_thread:
            self.delivery_thread.join(timeout=5)
        if self.port_thread:
            self.port_thread.join(timeout=5)

    def create_notification(
        self,
        title: str,
        message: str,
        severity: str = "info",
        event_type: str = "service_event",
        source: str = "system",
        payload: Optional[Dict[str, Any]] = None,
        resource_key: Optional[str] = None,
    ) -> int:
        severity = severity if severity in SEVERITY_ORDER else "info"
        with db_lock:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO notifications (
                        severity, event_type, source, title, message, payload, resource_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        severity,
                        event_type,
                        source,
                        title,
                        message,
                        json.dumps(payload or {}),
                        resource_key,
                    ),
                )
                notification_id = cursor.lastrowid
                cursor.execute(
                    """
                    INSERT INTO notification_deliveries (
                        notification_id, channel, target, status, attempt_count,
                        last_attempt_at, response_code, metadata
                    ) VALUES (?, 'in_app', 'global', 'delivered', 1, ?, 200, ?)
                    """,
                    (
                        notification_id,
                        datetime.utcnow().isoformat(),
                        json.dumps({"delivered_to": "in_app"}),
                    ),
                )
                conn.commit()
        self._queue_deliveries(notification_id, severity, event_type, payload or {})
        return notification_id

    def _queue_deliveries(self, notification_id: int, severity: str, event_type: str, payload: Dict[str, Any]):
        rule = self.get_rule(event_type)
        severity_rank = SEVERITY_ORDER.get(severity, 0)
        rule_rank = SEVERITY_ORDER.get(rule["min_severity"], 3)

        with db_lock:
            with self._connect() as conn:
                if rule["email_enabled"] and severity_rank >= rule_rank:
                    recipients = user_manager.get_email_recipients_for_severity(severity)
                    for recipient in recipients:
                        conn.execute(
                            """
                            INSERT INTO notification_deliveries (
                                notification_id, channel, target, status, metadata
                            ) VALUES (?, 'email', ?, 'pending', ?)
                            """,
                            (
                                notification_id,
                                recipient["email"],
                                json.dumps({"user_id": recipient["id"], "username": recipient["username"]}),
                            ),
                        )

                if rule["webhook_enabled"] and severity_rank >= rule_rank:
                    for webhook in self.list_webhooks(active_only=True):
                        webhook_rank = SEVERITY_ORDER.get(webhook["min_severity"], 3)
                        if severity_rank < webhook_rank:
                            continue
                        conn.execute(
                            """
                            INSERT INTO notification_deliveries (
                                notification_id, channel, target, status, metadata
                            ) VALUES (?, 'webhook', ?, 'pending', ?)
                            """,
                            (
                                notification_id,
                                webhook["url"],
                                json.dumps({"webhook_id": webhook["id"]}),
                            ),
                        )
                conn.commit()

    def _delivery_loop(self):
        while self.running:
            try:
                self._process_pending_deliveries()
            except Exception as exc:
                logger.error("Notification delivery loop error: %s", exc)
            time.sleep(1)

    def _process_pending_deliveries(self):
        now = datetime.utcnow().isoformat()
        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT d.*, n.title, n.message, n.severity, n.event_type, n.source, n.payload, n.resource_key
                    FROM notification_deliveries d
                    JOIN notifications n ON n.id = d.notification_id
                    WHERE d.status IN ('pending', 'retry')
                      AND d.next_attempt_at <= ?
                    ORDER BY d.id ASC
                    LIMIT 20
                    """,
                    (now,),
                ).fetchall()
        for row in rows:
            self._deliver_row(dict(row))

    def _deliver_row(self, row: Dict[str, Any]):
        metadata = json.loads(row["metadata"]) if row.get("metadata") else {}
        success = False
        response_code = None
        error_message = None
        try:
            if row["channel"] == "email":
                self._send_email(row["target"], row["title"], row["message"], row["severity"])
                success = True
                response_code = 250
            elif row["channel"] == "webhook":
                webhook = self.get_webhook(metadata.get("webhook_id"))
                if not webhook or not webhook["is_active"]:
                    raise RuntimeError("Webhook is inactive")
                response_code = self._send_webhook(webhook, row)
                success = True
            else:
                success = True
                response_code = 200
        except Exception as exc:
            error_message = str(exc)
            logger.error("Delivery failed for %s %s: %s", row["channel"], row["target"], exc)

        with db_lock:
            with self._connect() as conn:
                if success:
                    conn.execute(
                        """
                        UPDATE notification_deliveries
                        SET status = 'delivered',
                            attempt_count = attempt_count + 1,
                            last_attempt_at = ?,
                            response_code = ?,
                            last_error = NULL
                        WHERE id = ?
                        """,
                        (datetime.utcnow().isoformat(), response_code, row["id"]),
                    )
                else:
                    attempts = row["attempt_count"] + 1
                    if attempts >= 3:
                        status = "failed"
                        next_attempt = None
                    else:
                        status = "retry"
                        delay = self.retry_base_seconds * (2 ** (attempts - 1))
                        next_attempt = (datetime.utcnow() + timedelta(seconds=delay)).isoformat()
                    conn.execute(
                        """
                        UPDATE notification_deliveries
                        SET status = ?,
                            attempt_count = attempt_count + 1,
                            last_attempt_at = ?,
                            next_attempt_at = COALESCE(?, next_attempt_at),
                            last_error = ?,
                            response_code = ?
                        WHERE id = ?
                        """,
                        (
                            status,
                            datetime.utcnow().isoformat(),
                            next_attempt,
                            error_message,
                            response_code,
                            row["id"],
                        ),
                    )
                conn.commit()

    def _send_email(self, recipient: str, title: str, message: str, severity: str):
        smtp_host = os.getenv("TRUSTSCAN_SMTP_HOST")
        smtp_port = int(os.getenv("TRUSTSCAN_SMTP_PORT", "587"))
        smtp_username = os.getenv("TRUSTSCAN_SMTP_USERNAME")
        smtp_password = os.getenv("TRUSTSCAN_SMTP_PASSWORD")
        smtp_from = os.getenv("TRUSTSCAN_SMTP_FROM")
        use_tls = os.getenv("TRUSTSCAN_SMTP_TLS", "true").lower() != "false"

        if not smtp_host or not smtp_from:
            raise RuntimeError("SMTP is not configured")

        email = EmailMessage()
        email["Subject"] = f"[TrustScan {severity.upper()}] {title}"
        email["From"] = smtp_from
        email["To"] = recipient
        email.set_content(message)

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            if use_tls:
                server.starttls()
            if smtp_username and smtp_password:
                server.login(smtp_username, smtp_password)
            server.send_message(email)

    def _send_webhook(self, webhook: Dict[str, Any], row: Dict[str, Any]) -> int:
        payload = {
            "id": row["notification_id"],
            "title": row["title"],
            "message": row["message"],
            "severity": row["severity"],
            "event_type": row["event_type"],
            "source": row["source"],
            "resource_key": row["resource_key"],
            "payload": json.loads(row["payload"]) if row.get("payload") else {},
            "sent_at": datetime.utcnow().isoformat(),
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "TrustScan/1.0",
        }
        secret = webhook.get("secret") or ""
        if secret:
            signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-TrustScan-Signature"] = signature
        request_obj = urllib.request.Request(webhook["url"], data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request_obj, timeout=10) as response:
                return response.getcode()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Webhook failed with status {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Webhook error: {exc.reason}") from exc

    def _port_monitor_loop(self):
        while self.running and self.port_provider:
            try:
                snapshot = self._build_port_snapshot(self.port_provider())
                if self._last_port_snapshot is None:
                    self._last_port_snapshot = snapshot
                else:
                    self._emit_port_changes(self._last_port_snapshot, snapshot)
                    self._last_port_snapshot = snapshot
            except Exception as exc:
                logger.error("Port monitor error: %s", exc)
            time.sleep(self.port_poll_interval)

    def _build_port_snapshot(self, ports: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        snapshot = {}
        for port in ports:
            key = f"port:{port.get('protocol')}:{port.get('port')}"
            snapshot[key] = {
                "protocol": port.get("protocol"),
                "port": port.get("port"),
                "process_name": port.get("process_name"),
                "pid": port.get("pid"),
            }
        return snapshot

    def _emit_port_changes(self, previous: Dict[str, Dict[str, Any]], current: Dict[str, Dict[str, Any]]):
        previous_keys = set(previous)
        current_keys = set(current)
        opened = current_keys - previous_keys
        closed = previous_keys - current_keys

        for key in opened:
            port = current[key]
            self.create_notification(
                title=f"Port {port['port']} opened",
                message=f"{port['protocol']} port {port['port']} opened by {port['process_name']} ({port['pid']}).",
                severity="high",
                event_type="port_change",
                source="ports",
                payload=port,
                resource_key=key,
            )

        for key in closed:
            port = previous[key]
            self.create_notification(
                title=f"Port {port['port']} closed",
                message=f"{port['protocol']} port {port['port']} is no longer listening.",
                severity="medium",
                event_type="port_change",
                source="ports",
                payload=port,
                resource_key=key,
            )

    def get_notifications(self, user_id: int, limit: int = 25, unread_only: bool = False) -> Dict[str, Any]:
        query = """
            SELECT n.*, nr.read_at
            FROM notifications n
            LEFT JOIN notification_reads nr
              ON nr.notification_id = n.id AND nr.user_id = ?
        """
        params: List[Any] = [user_id]
        if unread_only:
            query += " WHERE nr.id IS NULL"
        query += " ORDER BY n.created_at DESC LIMIT ?"
        params.append(limit)

        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(query, tuple(params)).fetchall()
                unread_row = conn.execute(
                    """
                    SELECT COUNT(*) AS count
                    FROM notifications n
                    LEFT JOIN notification_reads nr
                      ON nr.notification_id = n.id AND nr.user_id = ?
                    WHERE nr.id IS NULL
                    """,
                    (user_id,),
                ).fetchone()

        notifications = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item["payload"]) if item.get("payload") else {}
            item["is_read"] = bool(item["read_at"])
            notifications.append(item)
        return {"items": notifications, "unread_count": unread_row["count"]}

    def mark_read(self, user_id: int, notification_id: int) -> bool:
        with db_lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO notification_reads (notification_id, user_id, read_at)
                    VALUES (?, ?, ?)
                    """,
                    (notification_id, user_id, datetime.utcnow().isoformat()),
                )
                conn.commit()
                return cursor.rowcount >= 0

    def mark_all_read(self, user_id: int) -> bool:
        with db_lock:
            with self._connect() as conn:
                notification_ids = conn.execute("SELECT id FROM notifications").fetchall()
                for row in notification_ids:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO notification_reads (notification_id, user_id, read_at)
                        VALUES (?, ?, ?)
                        """,
                        (row["id"], user_id, datetime.utcnow().isoformat()),
                    )
                conn.commit()
        return True

    def list_webhooks(self, active_only: bool = False) -> List[Dict[str, Any]]:
        query = "SELECT * FROM notification_webhooks"
        params: List[Any] = []
        if active_only:
            query += " WHERE is_active = 1"
        query += " ORDER BY created_at DESC"
        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def get_webhook(self, webhook_id: Optional[int]) -> Optional[Dict[str, Any]]:
        if not webhook_id:
            return None
        with db_lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM notification_webhooks WHERE id = ?",
                    (webhook_id,),
                ).fetchone()
        return dict(row) if row else None

    def create_webhook(
        self,
        name: str,
        url: str,
        secret: str = "",
        min_severity: str = "high",
        created_by: str = "system",
    ) -> int:
        with db_lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO notification_webhooks (name, url, secret, min_severity, created_by)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (name, url, secret, min_severity, created_by),
                )
                conn.commit()
                return cursor.lastrowid

    def delete_webhook(self, webhook_id: int) -> bool:
        with db_lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM notification_webhooks WHERE id = ?",
                    (webhook_id,),
                )
                conn.commit()
                return cursor.rowcount > 0

    def get_rules(self) -> List[Dict[str, Any]]:
        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM notification_rules ORDER BY event_type"
                ).fetchall()
        return [dict(row) for row in rows]

    def get_rule(self, event_type: str) -> Dict[str, Any]:
        with db_lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM notification_rules WHERE event_type = ?",
                    (event_type,),
                ).fetchone()
        if row:
            return dict(row)
        return {
            "event_type": event_type,
            "email_enabled": 1,
            "webhook_enabled": 1,
            "min_severity": "high",
        }

    def upsert_rule(
        self,
        event_type: str,
        email_enabled: bool,
        webhook_enabled: bool,
        min_severity: str,
    ) -> bool:
        with db_lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO notification_rules (event_type, email_enabled, webhook_enabled, min_severity, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(event_type) DO UPDATE SET
                        email_enabled = excluded.email_enabled,
                        webhook_enabled = excluded.webhook_enabled,
                        min_severity = excluded.min_severity,
                        updated_at = excluded.updated_at
                    """,
                    (
                        event_type,
                        int(email_enabled),
                        int(webhook_enabled),
                        min_severity,
                        datetime.utcnow().isoformat(),
                    ),
                )
                conn.commit()
        return True

    def get_delivery_attempts(self, notification_id: Optional[int] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM notification_deliveries"
        params: List[Any] = []
        if notification_id is not None:
            query += " WHERE notification_id = ?"
            params.append(notification_id)
        query += " ORDER BY created_at DESC"
        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(query, tuple(params)).fetchall()
        deliveries = []
        for row in rows:
            item = dict(row)
            item["metadata"] = json.loads(item["metadata"]) if item.get("metadata") else {}
            deliveries.append(item)
        return deliveries


notification_manager = NotificationManager()
