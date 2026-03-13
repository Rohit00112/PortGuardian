import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as app_module


def _rebind_manager_db(manager, attr_name: str, path: Path, init_method: str):
    setattr(manager, attr_name, str(path))
    getattr(manager, init_method)()


@pytest.fixture()
def client(tmp_path):
    app_module.stop_background_services()

    _rebind_manager_db(app_module.user_manager, "db_path", tmp_path / "users.db", "_init_database")
    _rebind_manager_db(app_module.notification_manager, "db_path", tmp_path / "notifications.db", "_init_database")
    app_module.notification_manager._seed_rules()
    app_module.notification_manager._last_port_snapshot = None
    _rebind_manager_db(app_module.managed_service_manager, "db_path", tmp_path / "services.db", "_init_database")
    app_module.managed_service_manager.processes = {}
    _rebind_manager_db(app_module.resource_limiter, "db_path", tmp_path / "limits.db", "init_database")
    app_module.resource_limiter.violation_counts = {}
    _rebind_manager_db(app_module.security_monitor, "db_path", tmp_path / "security.db", "init_database")
    app_module.security_monitor.connection_history.clear()
    app_module.security_monitor.port_access_history.clear()
    _rebind_manager_db(app_module.process_group_manager, "db_path", tmp_path / "groups.db", "init_database")
    _rebind_manager_db(app_module.enhanced_process_manager, "db_path", tmp_path / "history.db", "init_database")
    _rebind_manager_db(app_module.audit_logger, "db_path", tmp_path / "audit.db", "_init_database")
    _rebind_manager_db(app_module.api_key_manager, "db_path", tmp_path / "keys.db", "_init_database")

    app_module.app.config["TESTING"] = True

    with app_module.app.test_client() as client:
        yield client

    app_module.stop_background_services()


def login(client, username="admin", password="secretpass"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


def bootstrap_admin(client, username="admin", password="secretpass"):
    response = client.post(
        "/setup",
        data={
            "username": username,
            "email": "admin@example.com",
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302


def test_setup_and_login_flow(client):
    response = client.get("/setup")
    assert response.status_code == 200

    bootstrap_admin(client)
    login_response = login(client)
    assert login_response.status_code == 302
    assert login_response.headers["Location"].endswith(url_path("/"))


def test_viewer_rbac_blocks_admin_mutations(client):
    bootstrap_admin(client)
    assert login(client).status_code == 302

    app_module.user_manager.create_user("viewer", "viewerpass", role="viewer")
    client.get("/logout")
    assert client.post(
        "/login",
        data={"username": "viewer", "password": "viewerpass"},
        follow_redirects=False,
    ).status_code == 302

    assert client.get("/managed-services").status_code == 200
    forbidden = client.post(
        "/api/managed-services",
        json={"name": "denied", "command": "echo test"},
    )
    assert forbidden.status_code == 403


def test_dashboard_preferences_and_favorites_persist(client):
    bootstrap_admin(client)
    assert login(client).status_code == 302

    pref_response = client.post(
        "/api/dashboard/preferences",
        json={
            "widget_order": ["notifications", "services", "ports"],
            "widget_visibility": {"notifications": True, "services": True, "ports": False},
            "theme": "dark",
        },
    )
    assert pref_response.status_code == 200
    saved = app_module.user_manager.get_dashboard_preferences(1)
    assert saved["widget_order"][0] == "notifications"
    assert saved["widget_visibility"]["ports"] is False
    assert app_module.user_manager.get_user_by_id(1).theme == "dark"

    favorite_response = client.post(
        "/api/favorites",
        json={"resource_key": "process:1234", "resource_type": "process", "label": "Test Process"},
    )
    assert favorite_response.status_code == 201
    favorites = client.get("/api/favorites").get_json()["data"]
    assert favorites[0]["resource_key"] == "process:1234"


def test_notifications_support_port_change_and_read_state(client):
    bootstrap_admin(client)
    assert login(client).status_code == 302

    app_module.notification_manager._emit_port_changes(
        {},
        {
            "port:TCP:5000": {
                "protocol": "TCP",
                "port": 5000,
                "process_name": "python",
                "pid": 321,
            }
        },
    )

    inbox = client.get("/api/notifications").get_json()["data"]
    assert inbox["unread_count"] == 1
    assert inbox["items"][0]["title"] == "Port 5000 opened"

    notification_id = inbox["items"][0]["id"]
    read_response = client.post(f"/api/notifications/{notification_id}/read")
    assert read_response.status_code == 200
    updated = client.get("/api/notifications").get_json()["data"]
    assert updated["unread_count"] == 0


def test_managed_services_dependencies_schedules_and_restarts(client):
    bootstrap_admin(client)
    python_command = f'{sys.executable} -c "import time; time.sleep(3)"'
    crash_command = f'{sys.executable} -c "import sys; sys.exit(1)"'

    assert login(client).status_code == 302

    base_service = client.post(
        "/api/managed-services",
        json={"name": "base-service", "command": python_command, "restart_policy": "never"},
    ).get_json()["data"]["id"]
    dependent_service = client.post(
        "/api/managed-services",
        json={
            "name": "dependent-service",
            "command": python_command,
            "dependency_ids": [base_service],
            "restart_policy": "never",
        },
    ).get_json()["data"]["id"]

    blocked = client.post(f"/api/managed-services/{dependent_service}/start")
    assert blocked.status_code == 400

    started = client.post(f"/api/managed-services/{base_service}/start")
    assert started.status_code == 200

    dependency_started = client.post(f"/api/managed-services/{dependent_service}/start")
    assert dependency_started.status_code == 200

    schedule_service = client.post(
        "/api/managed-services",
        json={"name": "scheduled-service", "command": python_command, "restart_policy": "never"},
    ).get_json()["data"]["id"]
    schedule_response = client.post(
        f"/api/managed-services/{schedule_service}/schedules",
        json={
            "action": "start",
            "trigger_type": "interval",
            "trigger_config": {"seconds": 1},
        },
    )
    assert schedule_response.status_code == 201
    schedule_id = schedule_response.get_json()["data"]["id"]
    app_module.managed_service_manager._run_schedule(schedule_id, schedule_service, "start")
    assert app_module.managed_service_manager.get_service(schedule_service)["status"] == "running"

    crash_service = client.post(
        "/api/managed-services",
        json={
            "name": "crash-service",
            "command": crash_command,
            "restart_policy": "always",
            "restart_limit": 1,
        },
    ).get_json()["data"]["id"]
    assert client.post(f"/api/managed-services/{crash_service}/start").status_code == 200

    time.sleep(0.3)
    app_module.managed_service_manager._check_running_services()
    time.sleep(0.3)
    app_module.managed_service_manager._check_running_services()

    events = app_module.managed_service_manager.get_events(crash_service, limit=10)
    assert any(event["event_type"] == "restart_exhausted" for event in events)
    app_module.managed_service_manager.stop_service(base_service)
    app_module.managed_service_manager.stop_service(dependent_service)
    app_module.managed_service_manager.stop_service(schedule_service)


def url_path(path: str) -> str:
    return path
