import json
import logging
import os
import shlex
import signal
import sqlite3
import subprocess
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import psutil
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger


logger = logging.getLogger("managed_services")
db_lock = threading.Lock()


class ManagedServiceManager:
    """Launch, supervise, and schedule services started by TrustScan."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv("TRUSTSCAN_SERVICES_DB", "managed_services.db")
        self.scheduler = BackgroundScheduler()
        self.running = False
        self.supervisor_thread = None
        self.processes: Dict[int, subprocess.Popen] = {}
        self.runtime_lock = threading.Lock()
        self.event_callback: Optional[Callable[..., None]] = None
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
                    CREATE TABLE IF NOT EXISTS managed_services (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        command TEXT NOT NULL,
                        working_directory TEXT,
                        environment TEXT,
                        enabled BOOLEAN NOT NULL DEFAULT 1,
                        restart_policy TEXT NOT NULL DEFAULT 'on-failure',
                        restart_limit INTEGER NOT NULL DEFAULT 3,
                        current_pid INTEGER,
                        status TEXT NOT NULL DEFAULT 'stopped',
                        last_run_at DATETIME,
                        last_exit_code INTEGER,
                        restart_count INTEGER NOT NULL DEFAULT 0,
                        created_by TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS service_dependencies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service_id INTEGER NOT NULL,
                        dependency_service_id INTEGER NOT NULL,
                        UNIQUE(service_id, dependency_service_id)
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS service_schedules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service_id INTEGER NOT NULL,
                        action TEXT NOT NULL,
                        trigger_type TEXT NOT NULL,
                        trigger_config TEXT NOT NULL,
                        is_active BOOLEAN NOT NULL DEFAULT 1,
                        last_run_at DATETIME,
                        next_run_at DATETIME,
                        created_by TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS service_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service_id INTEGER NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL DEFAULT 'info',
                        message TEXT NOT NULL,
                        payload TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_services_status ON managed_services(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_service_events_service ON service_events(service_id)")
                conn.commit()

    def set_event_callback(self, callback: Callable[..., None]):
        self.event_callback = callback

    def start(self):
        if self.running:
            return
        if not self.scheduler.running:
            self.scheduler = BackgroundScheduler()
        self.running = True
        self._recover_runtime_state()
        self.sync_schedules()
        self.scheduler.start(paused=False)
        self.supervisor_thread = threading.Thread(target=self._supervisor_loop, daemon=True)
        self.supervisor_thread.start()

    def stop(self):
        self.running = False
        if self.supervisor_thread:
            self.supervisor_thread.join(timeout=5)
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
        self.scheduler = BackgroundScheduler()

    def _recover_runtime_state(self):
        services = self.list_services()
        for service in services:
            pid = service.get("current_pid")
            if pid and psutil.pid_exists(pid):
                self._update_service_state(service["id"], status="running")
            else:
                self._update_service_state(service["id"], status="stopped", current_pid=None)

    def list_services(self) -> List[Dict[str, Any]]:
        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM managed_services ORDER BY name"
                ).fetchall()
        services = []
        for row in rows:
            service = dict(row)
            service["environment"] = json.loads(service["environment"]) if service.get("environment") else {}
            service["dependencies"] = self.get_dependencies(service["id"])
            service["schedules"] = self.get_schedules(service["id"])
            service["events"] = self.get_events(service["id"], limit=6)
            services.append(service)
        return services

    def get_service(self, service_id: int) -> Optional[Dict[str, Any]]:
        with db_lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM managed_services WHERE id = ?",
                    (service_id,),
                ).fetchone()
        if not row:
            return None
        service = dict(row)
        service["environment"] = json.loads(service["environment"]) if service.get("environment") else {}
        service["dependencies"] = self.get_dependencies(service_id)
        service["schedules"] = self.get_schedules(service_id)
        service["events"] = self.get_events(service_id)
        return service

    def create_service(
        self,
        name: str,
        command: str,
        working_directory: str = "",
        environment: Optional[Dict[str, Any]] = None,
        enabled: bool = True,
        restart_policy: str = "on-failure",
        restart_limit: int = 3,
        dependency_ids: Optional[List[int]] = None,
        created_by: str = "system",
    ) -> int:
        if restart_policy not in {"never", "on-failure", "always"}:
            raise ValueError("Invalid restart policy")
        if not command.strip():
            raise ValueError("Command is required")
        try:
            with db_lock:
                with self._connect() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO managed_services (
                            name, command, working_directory, environment, enabled,
                            restart_policy, restart_limit, created_by
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            name.strip(),
                            command.strip(),
                            working_directory.strip() or None,
                            json.dumps(environment or {}),
                            int(enabled),
                            restart_policy,
                            int(restart_limit),
                            created_by,
                        ),
                    )
                    service_id = cursor.lastrowid
                    self._replace_dependencies(conn, service_id, dependency_ids or [])
                    conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("Service name already exists") from exc
        self._emit_event(service_id, "created", "info", f"Managed service '{name}' created.")
        return service_id

    def update_service(
        self,
        service_id: int,
        name: str,
        command: str,
        working_directory: str = "",
        environment: Optional[Dict[str, Any]] = None,
        enabled: bool = True,
        restart_policy: str = "on-failure",
        restart_limit: int = 3,
        dependency_ids: Optional[List[int]] = None,
    ) -> bool:
        try:
            with db_lock:
                with self._connect() as conn:
                    cursor = conn.execute(
                        """
                        UPDATE managed_services
                        SET name = ?, command = ?, working_directory = ?, environment = ?,
                            enabled = ?, restart_policy = ?, restart_limit = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            name.strip(),
                            command.strip(),
                            working_directory.strip() or None,
                            json.dumps(environment or {}),
                            int(enabled),
                            restart_policy,
                            int(restart_limit),
                            datetime.utcnow().isoformat(),
                            service_id,
                        ),
                    )
                    self._replace_dependencies(conn, service_id, dependency_ids or [])
                    conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("Service name already exists") from exc
        self.sync_schedules()
        return cursor.rowcount > 0

    def delete_service(self, service_id: int) -> bool:
        self.stop_service(service_id, requested_by="system")
        with db_lock:
            with self._connect() as conn:
                cursor = conn.execute("DELETE FROM managed_services WHERE id = ?", (service_id,))
                conn.execute("DELETE FROM service_dependencies WHERE service_id = ? OR dependency_service_id = ?", (service_id, service_id))
                conn.execute("DELETE FROM service_schedules WHERE service_id = ?", (service_id,))
                conn.commit()
        self.sync_schedules()
        return cursor.rowcount > 0

    def _replace_dependencies(self, conn: sqlite3.Connection, service_id: int, dependency_ids: List[int]):
        conn.execute("DELETE FROM service_dependencies WHERE service_id = ?", (service_id,))
        for dependency_id in dependency_ids:
            if int(dependency_id) == int(service_id):
                continue
            conn.execute(
                """
                INSERT OR IGNORE INTO service_dependencies (service_id, dependency_service_id)
                VALUES (?, ?)
                """,
                (service_id, int(dependency_id)),
            )

    def get_dependencies(self, service_id: int) -> List[Dict[str, Any]]:
        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT d.dependency_service_id AS id, s.name, s.status
                    FROM service_dependencies d
                    JOIN managed_services s ON s.id = d.dependency_service_id
                    WHERE d.service_id = ?
                    ORDER BY s.name
                    """,
                    (service_id,),
                ).fetchall()
        return [dict(row) for row in rows]

    def dependencies_satisfied(self, service_id: int) -> bool:
        dependencies = self.get_dependencies(service_id)
        return all(dep["status"] == "running" for dep in dependencies)

    def start_service(self, service_id: int, requested_by: str = "system", is_restart: bool = False) -> Dict[str, Any]:
        service = self.get_service(service_id)
        if not service:
            raise ValueError("Service not found")
        if not service["enabled"]:
            raise ValueError("Service is disabled")
        if not self.dependencies_satisfied(service_id):
            raise ValueError("Service dependencies are not running")
        if service.get("current_pid") and psutil.pid_exists(service["current_pid"]):
            return {"status": "success", "message": "Service is already running", "service_id": service_id}

        command = shlex.split(service["command"])
        env = os.environ.copy()
        env.update({str(k): str(v) for k, v in service.get("environment", {}).items()})
        process = subprocess.Popen(
            command,
            cwd=service.get("working_directory") or None,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        with self.runtime_lock:
            self.processes[service_id] = process
        restart_count = service["restart_count"] if is_restart else 0
        self._update_service_state(
            service_id,
            current_pid=process.pid,
            status="running",
            last_run_at=datetime.utcnow().isoformat(),
            last_exit_code=None,
            restart_count=restart_count,
        )
        verb = "restarted" if is_restart else "started"
        self._emit_event(
            service_id,
            verb,
            "high" if is_restart else "info",
            f"Service '{service['name']}' {verb} by {requested_by}.",
            {"pid": process.pid, "requested_by": requested_by},
        )
        return {"status": "success", "message": f"Service {verb}", "pid": process.pid, "service_id": service_id}

    def stop_service(self, service_id: int, requested_by: str = "system") -> Dict[str, Any]:
        service = self.get_service(service_id)
        if not service:
            raise ValueError("Service not found")

        pid = service.get("current_pid")
        process = None
        with self.runtime_lock:
            process = self.processes.pop(service_id, None)

        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        elif pid and psutil.pid_exists(pid):
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except ProcessLookupError:
                pass

        self._update_service_state(service_id, status="stopped", current_pid=None, last_exit_code=0)
        self._emit_event(
            service_id,
            "stopped",
            "info",
            f"Service '{service['name']}' stopped by {requested_by}.",
            {"requested_by": requested_by},
        )
        return {"status": "success", "message": "Service stopped", "service_id": service_id}

    def restart_service(self, service_id: int, requested_by: str = "system") -> Dict[str, Any]:
        self.stop_service(service_id, requested_by=requested_by)
        return self.start_service(service_id, requested_by=requested_by, is_restart=True)

    def add_schedule(
        self,
        service_id: int,
        action: str,
        trigger_type: str,
        trigger_config: Dict[str, Any],
        created_by: str = "system",
    ) -> int:
        if action not in {"start", "stop", "restart"}:
            raise ValueError("Invalid schedule action")
        if trigger_type not in {"once", "interval", "cron"}:
            raise ValueError("Invalid trigger type")
        with db_lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO service_schedules (
                        service_id, action, trigger_type, trigger_config, created_by
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (service_id, action, trigger_type, json.dumps(trigger_config), created_by),
                )
                conn.commit()
                schedule_id = cursor.lastrowid
        self.sync_schedules()
        self._emit_event(service_id, "schedule_created", "info", f"Schedule added for {action}.", {"schedule_id": schedule_id})
        return schedule_id

    def remove_schedule(self, schedule_id: int) -> bool:
        with db_lock:
            with self._connect() as conn:
                cursor = conn.execute("DELETE FROM service_schedules WHERE id = ?", (schedule_id,))
                conn.commit()
        self.sync_schedules()
        return cursor.rowcount > 0

    def get_schedules(self, service_id: int) -> List[Dict[str, Any]]:
        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM service_schedules WHERE service_id = ? ORDER BY created_at DESC",
                    (service_id,),
                ).fetchall()
        schedules = []
        for row in rows:
            schedule = dict(row)
            schedule["trigger_config"] = json.loads(schedule["trigger_config"]) if schedule.get("trigger_config") else {}
            schedules.append(schedule)
        return schedules

    def get_events(self, service_id: int, limit: int = 25) -> List[Dict[str, Any]]:
        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM service_events
                    WHERE service_id = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (service_id, limit),
                ).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            event["payload"] = json.loads(event["payload"]) if event.get("payload") else {}
            events.append(event)
        return events

    def sync_schedules(self):
        for job in list(self.scheduler.get_jobs()):
            self.scheduler.remove_job(job.id)

        with db_lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM service_schedules
                    WHERE is_active = 1
                    ORDER BY id
                    """
                ).fetchall()

        for row in rows:
            schedule = dict(row)
            trigger_config = json.loads(schedule["trigger_config"]) if schedule.get("trigger_config") else {}
            trigger = self._build_trigger(schedule["trigger_type"], trigger_config)
            job = self.scheduler.add_job(
                self._run_schedule,
                trigger=trigger,
                id=f"service-schedule-{schedule['id']}",
                args=[schedule["id"], schedule["service_id"], schedule["action"]],
                replace_existing=True,
            )
            next_run_time = getattr(job, "next_run_time", None)
            with db_lock:
                with self._connect() as conn:
                    conn.execute(
                        "UPDATE service_schedules SET next_run_at = ? WHERE id = ?",
                        (next_run_time.isoformat() if next_run_time else None, schedule["id"]),
                    )
                    conn.commit()

    def _build_trigger(self, trigger_type: str, config: Dict[str, Any]):
        if trigger_type == "once":
            return DateTrigger(run_date=config["run_date"])
        if trigger_type == "interval":
            seconds = int(config.get("seconds", 60))
            return IntervalTrigger(seconds=seconds)
        if trigger_type == "cron":
            return CronTrigger.from_crontab(config["expression"])
        raise ValueError("Unsupported trigger type")

    def _run_schedule(self, schedule_id: int, service_id: int, action: str):
        try:
            if action == "start":
                self.start_service(service_id, requested_by="scheduler")
            elif action == "stop":
                self.stop_service(service_id, requested_by="scheduler")
            elif action == "restart":
                self.restart_service(service_id, requested_by="scheduler")
            else:
                raise ValueError("Unsupported schedule action")

            next_run = None
            job = self.scheduler.get_job(f"service-schedule-{schedule_id}")
            if job and job.next_run_time:
                next_run = job.next_run_time.isoformat()
            with db_lock:
                with self._connect() as conn:
                    conn.execute(
                        """
                        UPDATE service_schedules
                        SET last_run_at = ?, next_run_at = ?
                        WHERE id = ?
                        """,
                        (datetime.utcnow().isoformat(), next_run, schedule_id),
                    )
                    conn.commit()
        except Exception as exc:
            self._emit_event(
                service_id,
                "schedule_failure",
                "high",
                f"Scheduled action '{action}' failed: {exc}",
                {"schedule_id": schedule_id, "action": action},
            )

    def _supervisor_loop(self):
        while self.running:
            try:
                self._check_running_services()
            except Exception as exc:
                logger.error("Managed services supervisor error: %s", exc)
            time.sleep(2)

    def _check_running_services(self):
        services = self.list_services()
        for service in services:
            if service["status"] != "running" or not service.get("current_pid"):
                continue
            process = None
            with self.runtime_lock:
                process = self.processes.get(service["id"])
            exit_code = None
            if process is not None:
                exit_code = process.poll()
            elif not psutil.pid_exists(service["current_pid"]):
                exit_code = -1

            if exit_code is None:
                continue

            with self.runtime_lock:
                self.processes.pop(service["id"], None)

            self._update_service_state(
                service["id"],
                status="failed" if exit_code else "stopped",
                current_pid=None,
                last_exit_code=exit_code,
            )
            self._emit_event(
                service["id"],
                "crashed" if exit_code else "exited",
                "critical" if exit_code else "medium",
                f"Service '{service['name']}' exited with code {exit_code}.",
                {"exit_code": exit_code},
            )
            if self._should_restart(service, exit_code):
                restart_count = service["restart_count"] + 1
                if restart_count > service["restart_limit"]:
                    self._update_service_state(service["id"], restart_count=restart_count)
                    self._emit_event(
                        service["id"],
                        "restart_exhausted",
                        "critical",
                        f"Service '{service['name']}' reached restart limit.",
                        {"restart_limit": service["restart_limit"]},
                    )
                    continue
                self._update_service_state(service["id"], restart_count=restart_count)
                try:
                    self.start_service(service["id"], requested_by="supervisor", is_restart=True)
                except Exception as exc:
                    self._emit_event(
                        service["id"],
                        "restart_failed",
                        "critical",
                        f"Service '{service['name']}' restart failed: {exc}",
                        {"restart_count": restart_count},
                    )

    def _should_restart(self, service: Dict[str, Any], exit_code: Optional[int]) -> bool:
        if service["restart_policy"] == "never":
            return False
        if service["restart_policy"] == "always":
            return True
        return bool(exit_code)

    def _update_service_state(self, service_id: int, **fields):
        if not fields:
            return
        updates = []
        values = []
        for key, value in fields.items():
            updates.append(f"{key} = ?")
            values.append(value)
        updates.append("updated_at = ?")
        values.append(datetime.utcnow().isoformat())
        values.append(service_id)
        with db_lock:
            with self._connect() as conn:
                conn.execute(
                    f"UPDATE managed_services SET {', '.join(updates)} WHERE id = ?",
                    tuple(values),
                )
                conn.commit()

    def _emit_event(
        self,
        service_id: int,
        event_type: str,
        severity: str,
        message: str,
        payload: Optional[Dict[str, Any]] = None,
    ):
        with db_lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO service_events (service_id, event_type, severity, message, payload)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (service_id, event_type, severity, message, json.dumps(payload or {})),
                )
                conn.commit()
        if self.event_callback:
            try:
                self.event_callback(
                    title="Managed service event",
                    message=message,
                    severity=severity,
                    event_type="schedule_failure" if event_type == "schedule_failure" else "service_event",
                    source="managed_services",
                    payload={"service_id": service_id, "event_type": event_type, **(payload or {})},
                    resource_key=f"service:{service_id}",
                )
            except Exception as exc:
                logger.error("Failed to forward service event: %s", exc)


managed_service_manager = ManagedServiceManager()
