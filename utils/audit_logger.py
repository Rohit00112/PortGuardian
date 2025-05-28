import json
import logging
import os
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, List
import sqlite3
import threading

# Thread-safe database operations
db_lock = threading.Lock()

class AuditEventType(Enum):
    """Enumeration of audit event types."""
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PROCESS_KILL = "process_kill"
    PROCESS_VIEW = "process_view"
    PROCESS_MANAGEMENT = "process_management"
    SYSTEM_HEALTH_VIEW = "system_health_view"
    DATA_EXPORT = "data_export"
    THEME_CHANGE = "theme_change"
    PAGE_ACCESS = "page_access"
    API_ACCESS = "api_access"
    ERROR = "error"
    SECURITY_VIOLATION = "security_violation"

class AuditSeverity(Enum):
    """Enumeration of audit event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AuditLogger:
    """Comprehensive audit logging system for PortGuardian."""

    def __init__(self, db_path: str = "audit_logs.db"):
        self.db_path = db_path
        self.logger = logging.getLogger('audit_logger')
        self._init_database()
        self._setup_file_logging()

    def _init_database(self):
        """Initialize the SQLite database for audit logs."""
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create audit_logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    user_id TEXT,
                    username TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    resource TEXT,
                    action TEXT,
                    details TEXT,
                    success BOOLEAN,
                    error_message TEXT,
                    session_id TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create indexes for better query performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON audit_logs(event_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON audit_logs(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON audit_logs(severity)')

            conn.commit()
            conn.close()

    def _setup_file_logging(self):
        """Setup file-based logging as backup."""
        handler = logging.FileHandler('audit.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def log_event(self,
                  event_type: AuditEventType,
                  severity: AuditSeverity = AuditSeverity.LOW,
                  user_id: Optional[str] = None,
                  username: Optional[str] = None,
                  ip_address: Optional[str] = None,
                  user_agent: Optional[str] = None,
                  resource: Optional[str] = None,
                  action: Optional[str] = None,
                  details: Optional[Dict[str, Any]] = None,
                  success: bool = True,
                  error_message: Optional[str] = None,
                  session_id: Optional[str] = None):
        """Log an audit event to both database and file."""

        timestamp = datetime.now().isoformat()
        details_json = json.dumps(details) if details else None

        # Log to database
        try:
            with db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT INTO audit_logs
                    (timestamp, event_type, severity, user_id, username, ip_address,
                     user_agent, resource, action, details, success, error_message, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    timestamp, event_type.value, severity.value, user_id, username,
                    ip_address, user_agent, resource, action, details_json,
                    success, error_message, session_id
                ))

                conn.commit()
                conn.close()
        except Exception as e:
            self.logger.error(f"Failed to log audit event to database: {str(e)}")

        # Log to file as backup
        log_entry = {
            'timestamp': timestamp,
            'event_type': event_type.value,
            'severity': severity.value,
            'user_id': user_id,
            'username': username,
            'ip_address': ip_address,
            'resource': resource,
            'action': action,
            'success': success,
            'error_message': error_message,
            'details': details
        }

        self.logger.info(json.dumps(log_entry))

    def get_logs(self,
                 limit: int = 100,
                 offset: int = 0,
                 event_type: Optional[AuditEventType] = None,
                 severity: Optional[AuditSeverity] = None,
                 user_id: Optional[str] = None,
                 start_date: Optional[str] = None,
                 end_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve audit logs with filtering options."""

        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Build query with filters
            query = "SELECT * FROM audit_logs WHERE 1=1"
            params = []

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type.value)

            if severity:
                query += " AND severity = ?"
                params.append(severity.value)

            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)

            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)
            columns = [description[0] for description in cursor.description]
            rows = cursor.fetchall()

            conn.close()

            # Convert to list of dictionaries
            logs = []
            for row in rows:
                log_dict = dict(zip(columns, row))
                # Parse JSON details if present
                if log_dict.get('details'):
                    try:
                        log_dict['details'] = json.loads(log_dict['details'])
                    except json.JSONDecodeError:
                        pass
                logs.append(log_dict)

            return logs

    def get_log_statistics(self) -> Dict[str, Any]:
        """Get statistics about audit logs."""

        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Total logs
            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            total_logs = cursor.fetchone()[0]

            # Logs by event type
            cursor.execute("""
                SELECT event_type, COUNT(*) as count
                FROM audit_logs
                GROUP BY event_type
                ORDER BY count DESC
            """)
            event_type_stats = dict(cursor.fetchall())

            # Logs by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM audit_logs
                GROUP BY severity
                ORDER BY count DESC
            """)
            severity_stats = dict(cursor.fetchall())

            # Recent activity (last 24 hours)
            cursor.execute("""
                SELECT COUNT(*) FROM audit_logs
                WHERE datetime(timestamp) >= datetime('now', '-1 day')
            """)
            recent_activity = cursor.fetchone()[0]

            # Failed events
            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE success = 0")
            failed_events = cursor.fetchone()[0]

            # Top users by activity
            cursor.execute("""
                SELECT username, COUNT(*) as count
                FROM audit_logs
                WHERE username IS NOT NULL
                GROUP BY username
                ORDER BY count DESC
                LIMIT 10
            """)
            top_users = dict(cursor.fetchall())

            conn.close()

            return {
                'total_logs': total_logs,
                'event_type_stats': event_type_stats,
                'severity_stats': severity_stats,
                'recent_activity': recent_activity,
                'failed_events': failed_events,
                'top_users': top_users
            }

    def export_logs(self,
                    format: str = 'json',
                    start_date: Optional[str] = None,
                    end_date: Optional[str] = None) -> str:
        """Export audit logs in specified format."""

        logs = self.get_logs(
            limit=10000,  # Large limit for export
            start_date=start_date,
            end_date=end_date
        )

        if format.lower() == 'json':
            return json.dumps(logs, indent=2)
        elif format.lower() == 'csv':
            import csv
            import io

            output = io.StringIO()
            if logs:
                writer = csv.DictWriter(output, fieldnames=logs[0].keys())
                writer.writeheader()
                for log in logs:
                    # Convert details dict to string for CSV
                    if isinstance(log.get('details'), dict):
                        log['details'] = json.dumps(log['details'])
                    writer.writerow(log)

            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")

# Global audit logger instance
audit_logger = AuditLogger()
