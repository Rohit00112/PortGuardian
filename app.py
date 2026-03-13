import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

from api.endpoints import api_bp
from utils.api_auth import api_key_manager
from utils.audit_decorators import audit_action, audit_login_attempt, audit_logout, audit_process_kill
from utils.audit_logger import AuditEventType, AuditSeverity, audit_logger
from utils.authz import admin_required
from utils.enhanced_process_manager import enhanced_process_manager
from utils.managed_services import managed_service_manager
from utils.metrics_collector import metrics_collector
from utils.metrics_storage import metrics_storage
from utils.notifications import notification_manager
from utils.port_scanner import get_open_ports
from utils.process_groups import process_group_manager
from utils.process_manager import get_process_info, kill_process
from utils.resource_limiter import resource_limiter
from utils.security_monitor import security_monitor
from utils.system_monitor import get_all_system_metrics
from utils.users import SEVERITY_ORDER, user_manager


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename="app.log",
    filemode="a",
)
logger = logging.getLogger("trustscan")


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("TRUSTSCAN_SECRET_KEY", "trustscan-dev-secret")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["JSON_SORT_KEYS"] = False

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

app.register_blueprint(api_bp)


managed_service_manager.set_event_callback(notification_manager.create_notification)
resource_limiter.set_event_callback(notification_manager.create_notification)
security_monitor.set_event_callback(notification_manager.create_notification)


def _is_api_request() -> bool:
    return request.path.startswith("/api/")


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _sort_ports(ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def sort_key(port: Dict[str, Any]):
        port_value = port.get("port")
        if isinstance(port_value, int):
            return (0, port_value, str(port.get("protocol", "")))
        return (1, str(port_value), str(port.get("protocol", "")))

    return sorted(ports, key=sort_key)


def _get_ports_snapshot(limit: Optional[int] = None) -> Dict[str, Any]:
    ports = _sort_ports(get_open_ports())
    permission_error = bool(ports and ports[0].get("process_name") == "Permission Denied")
    if limit is not None:
        ports = ports[:limit]
    return {"ports": ports, "permission_error": permission_error}


def _get_service_summary(services: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "total": len(services),
        "running": sum(1 for service in services if service.get("status") == "running"),
        "failed": sum(1 for service in services if service.get("status") == "failed"),
        "scheduled": sum(1 for service in services if service.get("schedules")),
    }


def _resolve_favorites(favorites: List[Dict[str, Any]], ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    port_map = {f"port:{port['protocol']}:{port['port']}": port for port in ports if port.get("port") != "N/A"}
    resolved = []
    for favorite in favorites:
        resource_key = favorite["resource_key"]
        item = {"favorite": favorite, "kind": favorite["resource_type"], "data": None, "available": True}
        if resource_key.startswith("port:"):
            item["data"] = port_map.get(resource_key)
            item["available"] = item["data"] is not None
        elif resource_key.startswith("process:"):
            pid = _safe_int(resource_key.split(":", 1)[1], 0)
            item["data"] = get_process_info(pid) if pid else None
            item["available"] = item["data"] is not None
        elif resource_key.startswith("service:"):
            service_id = _safe_int(resource_key.split(":", 1)[1], 0)
            item["data"] = managed_service_manager.get_service(service_id) if service_id else None
            item["available"] = item["data"] is not None
        resolved.append(item)
    return resolved


def _dashboard_context() -> Dict[str, Any]:
    ports_snapshot = _get_ports_snapshot(limit=10)
    ports = ports_snapshot["ports"]
    metrics = get_all_system_metrics()
    services = managed_service_manager.list_services()
    notifications = notification_manager.get_notifications(current_user.id, limit=6)
    favorites = user_manager.get_favorites(current_user.id)
    return {
        "metrics": metrics,
        "system_summary": {
            "cpu": metrics.get("cpu_info", {}).get("overall_percent", 0),
            "memory": metrics.get("memory_info", {}).get("virtual", {}).get("percent", 0),
            "uptime": metrics.get("uptime_info", {}).get("uptime_formatted", "Unavailable"),
            "load": metrics.get("load_info", {}).get("load_1_min", 0),
        },
        "ports": ports,
        "permission_error": ports_snapshot["permission_error"],
        "service_summary": _get_service_summary(services),
        "services": services[:6],
        "threats": security_monitor.get_recent_threats(hours=24, limit=6),
        "audit_logs": audit_logger.get_logs(limit=6),
        "notifications": notifications["items"],
        "notification_unread_count": notifications["unread_count"],
        "favorites": _resolve_favorites(favorites, ports),
        "dashboard_preferences": user_manager.get_dashboard_preferences(current_user.id),
    }


def _notification_preferences_context() -> Dict[str, Any]:
    return {
        "email": current_user.email or "",
        "email_notifications": bool(current_user.email_notifications),
        "notification_min_severity": current_user.notification_min_severity,
        "severity_order": list(SEVERITY_ORDER.keys()),
    }


def _update_audit_for_user_change(action: str, details: Dict[str, Any]):
    audit_logger.log_event(
        event_type=AuditEventType.PROCESS_MANAGEMENT,
        severity=AuditSeverity.MEDIUM,
        user_id=str(current_user.id) if current_user.is_authenticated else None,
        username=current_user.username if current_user.is_authenticated else None,
        ip_address=request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr),
        user_agent=request.headers.get("User-Agent", ""),
        resource="users",
        action=action,
        details=details,
    )


@login_manager.user_loader
def load_user(user_id):
    return user_manager.get_user_by_id(_safe_int(user_id, 0))


@login_manager.unauthorized_handler
def unauthorized():
    if _is_api_request():
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    return redirect(url_for("login"))


@app.before_request
def require_bootstrap():
    if user_manager.has_users():
        return None

    allowed_endpoints = {"setup", "login", "static"}
    if request.endpoint in allowed_endpoints or request.path.startswith("/api/v1"):
        return None
    if _is_api_request():
        return jsonify({"status": "error", "message": "Run initial setup first"}), 503
    return redirect(url_for("setup"))


@app.context_processor
def inject_shell_context():
    unread_count = 0
    if current_user.is_authenticated:
        unread_count = notification_manager.get_notifications(current_user.id, limit=5)["unread_count"]
    return {
        "app_name": "TrustScan",
        "is_admin": bool(current_user.is_authenticated and current_user.role == "admin"),
        "current_theme": current_user.theme if current_user.is_authenticated else "system",
        "notification_unread_count": unread_count,
    }


@app.errorhandler(401)
def handle_401(error):
    if _is_api_request():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    flash("Authentication is required.", "danger")
    return redirect(url_for("login"))


@app.errorhandler(403)
def handle_403(error):
    if _is_api_request():
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    flash("You do not have permission to perform that action.", "danger")
    return redirect(url_for("index"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if user_manager.has_users():
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip() or None

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("setup.html")
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("setup.html")

        user_manager.create_user(username=username, password=password, role="admin", email=email)
        audit_logger.log_event(
            event_type=AuditEventType.LOGIN,
            severity=AuditSeverity.HIGH,
            username=username,
            resource="setup",
            action="create_first_admin",
            details={"email": email},
            success=True,
        )
        flash("Initial admin account created. You can sign in now.", "success")
        return redirect(url_for("login"))

    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if not user_manager.has_users():
        return redirect(url_for("setup"))
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = user_manager.authenticate(username, password)
        if user:
            login_user(user)
            audit_login_attempt(success=True, username=username)
            return redirect(url_for("index"))

        audit_login_attempt(success=False, username=username, error_message="Invalid credentials")
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    username = current_user.username
    audit_logout(username)
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
@audit_action(AuditEventType.PAGE_ACCESS, AuditSeverity.LOW, resource="dashboard", action="view_overview")
def index():
    return render_template("index.html", **_dashboard_context())


@app.route("/ports")
@login_required
@audit_action(AuditEventType.PAGE_ACCESS, AuditSeverity.LOW, resource="ports", action="view_ports")
def ports_page():
    ports_snapshot = _get_ports_snapshot()
    favorite_keys = {favorite["resource_key"] for favorite in user_manager.get_favorites(current_user.id)}
    return render_template(
        "ports.html",
        ports=ports_snapshot["ports"],
        permission_error=ports_snapshot["permission_error"],
        favorite_keys=favorite_keys,
    )


@app.route("/process/<int:pid>")
@login_required
@audit_action(AuditEventType.PROCESS_VIEW, AuditSeverity.LOW, resource="process", action="view_process_details")
def process_detail(pid):
    process_info = get_process_info(pid)
    if not process_info:
        flash("Process not found.", "danger")
        return redirect(url_for("ports_page"))
    return render_template("process_detail.html", process=process_info)


@app.route("/process/<int:pid>/details")
@login_required
@audit_action(AuditEventType.PROCESS_VIEW, AuditSeverity.LOW, resource="process", action="view_enhanced_process")
def enhanced_process_details(pid):
    process_info = enhanced_process_manager.get_enhanced_process_info(pid)
    if not process_info:
        flash(f"Process with PID {pid} not found.", "danger")
        return redirect(url_for("ports_page"))
    return render_template("enhanced_process_details.html", process=process_info, pid=pid)


@app.route("/kill/<int:pid>", methods=["POST"])
@login_required
@admin_required
def kill_process_route(pid):
    process_info = get_process_info(pid)
    process_name = process_info.get("name", "Unknown") if process_info else "Unknown"
    result = kill_process(pid, user_id=current_user.username)
    audit_process_kill(
        pid=pid,
        process_name=process_name,
        success=result["success"],
        error_message=result["message"] if not result["success"] else None,
    )
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or _is_api_request():
        return jsonify(result)
    flash(result["message"], "success" if result["success"] else "danger")
    return redirect(url_for("ports_page"))


@app.route("/charts")
@login_required
def charts():
    return render_template("charts.html")


@app.route("/system-health")
@login_required
@audit_action(AuditEventType.SYSTEM_HEALTH_VIEW, AuditSeverity.LOW, resource="system", action="view_system_health")
def system_health():
    metrics = get_all_system_metrics()
    return render_template("system_health.html", metrics=metrics)


@app.route("/audit-logs")
@login_required
@audit_action(AuditEventType.PAGE_ACCESS, AuditSeverity.MEDIUM, resource="audit", action="view_audit_logs")
def audit_logs():
    event_type = request.args.get("event_type")
    severity = request.args.get("severity")
    user_id = request.args.get("user_id")
    page = max(_safe_int(request.args.get("page"), 1), 1)
    per_page = max(_safe_int(request.args.get("per_page"), 50), 1)

    event_enum = AuditEventType(event_type) if event_type in {item.value for item in AuditEventType} else None
    severity_enum = AuditSeverity(severity) if severity in {item.value for item in AuditSeverity} else None
    logs = audit_logger.get_logs(
        limit=per_page,
        offset=(page - 1) * per_page,
        event_type=event_enum,
        severity=severity_enum,
        user_id=user_id,
    )
    return render_template(
        "audit_logs.html",
        logs=logs,
        stats=audit_logger.get_log_statistics(),
        page=page,
        per_page=per_page,
        event_types=[event.value for event in AuditEventType],
        severities=[severity.value for severity in AuditSeverity],
        selected_event_type=event_type,
        selected_severity=severity,
        selected_user_id=user_id,
    )


@app.route("/export-audit-logs")
@login_required
@audit_action(AuditEventType.DATA_EXPORT, AuditSeverity.HIGH, resource="audit", action="export_audit_logs")
def export_audit_logs():
    format_type = request.args.get("format", "json").lower()
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    exported_data = audit_logger.export_logs(format=format_type, start_date=start_date, end_date=end_date)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"audit_logs_{timestamp}.{format_type}"
    if format_type == "json":
        return jsonify({"filename": filename, "data": exported_data, "timestamp": timestamp})
    return Response(
        exported_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/api-management")
@login_required
@admin_required
def api_management():
    return render_template("api_management.html")


@app.route("/export")
@login_required
@audit_action(AuditEventType.DATA_EXPORT, AuditSeverity.MEDIUM, resource="system_data", action="export_port_data")
def export_data():
    snapshot = _get_ports_snapshot()
    return jsonify({"timestamp": datetime.utcnow().isoformat(), "ports": snapshot["ports"]})


@app.route("/process-groups")
@login_required
def process_groups():
    return render_template(
        "process_groups.html",
        groups=process_group_manager.get_groups(),
        predefined=process_group_manager.get_predefined_groups(),
    )


@app.route("/security-dashboard")
@login_required
def security_dashboard():
    return render_template(
        "security_dashboard.html",
        threats=security_monitor.get_recent_threats(hours=24, limit=50),
        stats=security_monitor.get_threat_statistics(),
        monitoring_active=security_monitor.monitoring,
    )


@app.route("/resource-limits")
@login_required
def resource_limits():
    return render_template(
        "resource_limits.html",
        limits=resource_limiter.get_all_limits(),
        violations=resource_limiter.get_violations(hours=24, limit=50),
        templates=resource_limiter.get_templates(),
    )


@app.route("/managed-services")
@login_required
def managed_services_page():
    services = managed_service_manager.list_services()
    return render_template(
        "managed_services.html",
        services=services,
        all_services=services,
        service_summary=_get_service_summary(services),
    )


@app.route("/notifications")
@login_required
def notifications_page():
    notification_data = notification_manager.get_notifications(current_user.id, limit=100)
    return render_template(
        "notifications.html",
        notifications=notification_data["items"],
        unread_count=notification_data["unread_count"],
        webhooks=notification_manager.list_webhooks() if current_user.role == "admin" else [],
        rules=notification_manager.get_rules() if current_user.role == "admin" else [],
        notification_preferences=_notification_preferences_context(),
    )


@app.route("/settings/users")
@login_required
@admin_required
def user_settings_page():
    return render_template("user_settings.html", users=user_manager.list_users())


@app.route("/api/ports")
@login_required
def api_ports():
    snapshot = _get_ports_snapshot()
    return jsonify(snapshot["ports"])


@app.route("/api/process/<int:pid>")
@login_required
def api_process(pid):
    process_info = get_process_info(pid)
    if not process_info:
        return jsonify({"status": "error", "message": "Process not found"}), 404
    return jsonify(process_info)


@app.route("/api/process/<int:pid>/enhanced")
@login_required
def api_enhanced_process_info(pid):
    process_info = enhanced_process_manager.get_enhanced_process_info(pid)
    if not process_info:
        return jsonify({"status": "error", "message": "Process not found"}), 404
    return jsonify({"status": "success", "data": process_info})


@app.route("/api/process/<int:pid>/history")
@login_required
def api_process_history(pid):
    hours = max(_safe_int(request.args.get("hours"), 24), 1)
    return jsonify({"status": "success", "data": enhanced_process_manager._get_process_history(pid, hours)})


@app.route("/api/process/<int:pid>/trends")
@login_required
def api_process_trends(pid):
    return jsonify({"status": "success", "data": enhanced_process_manager._get_resource_trends(pid)})


@app.route("/api/process/<int:pid>/events")
@login_required
def api_process_events(pid):
    limit = max(_safe_int(request.args.get("limit"), 50), 1)
    return jsonify({"status": "success", "data": enhanced_process_manager._get_process_events(pid, limit)})


@app.route("/api/chart-data/<metric_type>")
@login_required
def api_chart_data(metric_type):
    hours = max(_safe_int(request.args.get("hours"), 24), 1)
    metric_mappings = {
        "cpu": ["overall_percent", "core_0_percent", "core_1_percent"],
        "memory": ["virtual_percent", "swap_percent"],
        "load": ["load_1_min", "load_5_min", "load_15_min"],
        "disk": [],
        "network": [],
    }

    if metric_type == "disk":
        recent_metrics = metrics_storage.get_metrics(metric_type="disk", limit=25)
        metric_mappings["disk"] = [metric["metric_name"] for metric in recent_metrics if metric["metric_name"].endswith("_percent")][:5]
    elif metric_type == "network":
        recent_metrics = metrics_storage.get_metrics(metric_type="network", limit=25)
        names = set()
        for metric in recent_metrics:
            name = metric["metric_name"]
            if name.endswith("_bytes_sent"):
                interface = name.replace("_bytes_sent", "")
                names.add(f"{interface}_bytes_sent")
                names.add(f"{interface}_bytes_recv")
        metric_mappings["network"] = list(names)[:6]

    metric_names = metric_mappings.get(metric_type, [])
    if not metric_names:
        return jsonify({"status": "error", "message": f"No metrics available for {metric_type}"}), 404
    return jsonify(metrics_storage.get_chart_data(metric_type, metric_names, hours))


@app.route("/api/metrics/collect")
@login_required
@admin_required
def api_collect_metrics():
    metrics_collector.collect_now()
    return jsonify({"success": True, "message": "Metrics collected"})


@app.route("/api/system-health")
@login_required
def api_system_health():
    return jsonify(get_all_system_metrics())


@app.route("/api/dashboard/preferences", methods=["GET", "POST"])
@login_required
def api_dashboard_preferences():
    if request.method == "GET":
        preferences = user_manager.get_dashboard_preferences(current_user.id)
        return jsonify({"status": "success", "data": preferences})

    data = request.get_json() or {}
    preferences = user_manager.save_dashboard_preferences(
        current_user.id,
        widget_order=data.get("widget_order"),
        widget_visibility=data.get("widget_visibility"),
    )
    if data.get("theme"):
        user_manager.set_theme(current_user.id, data["theme"])
    return jsonify({"status": "success", "data": preferences})


@app.route("/api/favorites", methods=["GET", "POST", "DELETE"])
@login_required
def api_favorites():
    if request.method == "GET":
        return jsonify({"status": "success", "data": user_manager.get_favorites(current_user.id)})

    data = request.get_json(silent=True) or {}
    if request.method == "POST":
        required = ["resource_key", "resource_type", "label"]
        missing = [field for field in required if field not in data]
        if missing:
            return jsonify({"status": "error", "message": f"Missing fields: {', '.join(missing)}"}), 400
        favorite = user_manager.add_favorite(
            current_user.id,
            resource_key=data["resource_key"],
            resource_type=data["resource_type"],
            label=data["label"],
            metadata=data.get("metadata"),
        )
        return jsonify({"status": "success", "data": favorite}), 201

    resource_key = data.get("resource_key") or request.args.get("resource_key")
    if not resource_key:
        return jsonify({"status": "error", "message": "resource_key is required"}), 400
    removed = user_manager.remove_favorite(current_user.id, resource_key)
    if not removed:
        return jsonify({"status": "error", "message": "Favorite not found"}), 404
    return jsonify({"status": "success"})


@app.route("/api/notifications")
@login_required
def api_notifications():
    limit = max(_safe_int(request.args.get("limit"), 25), 1)
    unread_only = request.args.get("unread_only") == "true"
    return jsonify({"status": "success", "data": notification_manager.get_notifications(current_user.id, limit=limit, unread_only=unread_only)})


@app.route("/api/notifications/<int:notification_id>/read", methods=["POST"])
@login_required
def api_mark_notification_read(notification_id):
    notification_manager.mark_read(current_user.id, notification_id)
    return jsonify({"status": "success"})


@app.route("/api/notifications/read-all", methods=["POST"])
@login_required
def api_mark_all_notifications_read():
    notification_manager.mark_all_read(current_user.id)
    return jsonify({"status": "success"})


@app.route("/api/notifications/preferences", methods=["POST"])
@login_required
def api_notification_preferences():
    data = request.get_json() or {}
    severity = data.get("notification_min_severity", current_user.notification_min_severity)
    if severity not in SEVERITY_ORDER:
        return jsonify({"status": "error", "message": "Invalid severity"}), 400
    user_manager.set_notification_preferences(
        current_user.id,
        email_notifications=bool(data.get("email_notifications")),
        notification_min_severity=severity,
        email=data.get("email", current_user.email),
    )
    return jsonify({"status": "success"})


@app.route("/api/save-theme", methods=["POST"])
@login_required
def save_theme():
    data = request.get_json() or {}
    theme = data.get("theme", "system")
    user_manager.set_theme(current_user.id, theme)
    return jsonify({"success": True, "theme": theme})


@app.route("/api/webhooks", methods=["GET", "POST"])
@login_required
@admin_required
def api_webhooks():
    if request.method == "GET":
        return jsonify({"status": "success", "data": notification_manager.list_webhooks()})

    data = request.get_json() or {}
    required = ["name", "url"]
    missing = [field for field in required if field not in data or not data[field]]
    if missing:
        return jsonify({"status": "error", "message": f"Missing fields: {', '.join(missing)}"}), 400
    webhook_id = notification_manager.create_webhook(
        name=data["name"],
        url=data["url"],
        secret=data.get("secret", ""),
        min_severity=data.get("min_severity", "high"),
        created_by=current_user.username,
    )
    return jsonify({"status": "success", "data": {"id": webhook_id}}), 201


@app.route("/api/webhooks/<int:webhook_id>", methods=["DELETE"])
@login_required
@admin_required
def api_delete_webhook(webhook_id):
    if not notification_manager.delete_webhook(webhook_id):
        return jsonify({"status": "error", "message": "Webhook not found"}), 404
    return jsonify({"status": "success"})


@app.route("/api/notification-rules", methods=["GET", "POST"])
@login_required
@admin_required
def api_notification_rules():
    if request.method == "GET":
        return jsonify({"status": "success", "data": notification_manager.get_rules()})

    data = request.get_json() or {}
    required = ["event_type", "email_enabled", "webhook_enabled", "min_severity"]
    missing = [field for field in required if field not in data]
    if missing:
        return jsonify({"status": "error", "message": f"Missing fields: {', '.join(missing)}"}), 400
    notification_manager.upsert_rule(
        event_type=data["event_type"],
        email_enabled=bool(data["email_enabled"]),
        webhook_enabled=bool(data["webhook_enabled"]),
        min_severity=data["min_severity"],
    )
    return jsonify({"status": "success"})


@app.route("/api/users", methods=["GET", "POST"])
@login_required
@admin_required
def api_users():
    if request.method == "GET":
        return jsonify({"status": "success", "data": user_manager.list_users()})

    data = request.get_json() or {}
    required = ["username", "password", "role"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"status": "error", "message": f"Missing fields: {', '.join(missing)}"}), 400
    try:
        user_id = user_manager.create_user(
            username=data["username"],
            password=data["password"],
            role=data["role"],
            email=data.get("email"),
            email_notifications=bool(data.get("email_notifications")),
            notification_min_severity=data.get("notification_min_severity", "high"),
        )
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    _update_audit_for_user_change("create_user", {"user_id": user_id, "username": data["username"], "role": data["role"]})
    return jsonify({"status": "success", "data": {"id": user_id}}), 201


@app.route("/api/users/<int:user_id>", methods=["PUT"])
@login_required
@admin_required
def api_update_user(user_id):
    data = request.get_json() or {}
    admin_count = sum(1 for user in user_manager.list_users() if user["role"] == "admin" and user["is_active"])
    target_user = user_manager.get_user_by_id(user_id)
    if not target_user:
        return jsonify({"status": "error", "message": "User not found"}), 404
    new_role = data.get("role", target_user.role)
    new_active = bool(data.get("is_active", target_user.is_active))
    if target_user.role == "admin" and admin_count == 1 and (new_role != "admin" or not new_active):
        return jsonify({"status": "error", "message": "At least one active admin is required"}), 400

    try:
        updated = user_manager.update_user(
            user_id,
            username=data.get("username"),
            password=data.get("password"),
            role=new_role,
            email=data.get("email"),
            is_active=new_active,
            email_notifications=data.get("email_notifications"),
            notification_min_severity=data.get("notification_min_severity"),
            theme=data.get("theme"),
        )
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    _update_audit_for_user_change("update_user", {"user_id": user_id, "role": new_role, "is_active": new_active})
    return jsonify({"status": "success", "updated": updated})


@app.route("/api/audit-logs")
@login_required
def api_audit_logs():
    event_type = request.args.get("event_type")
    severity = request.args.get("severity")
    user_id = request.args.get("user_id")
    limit = max(_safe_int(request.args.get("limit"), 100), 1)
    offset = max(_safe_int(request.args.get("offset"), 0), 0)
    event_enum = AuditEventType(event_type) if event_type in {item.value for item in AuditEventType} else None
    severity_enum = AuditSeverity(severity) if severity in {item.value for item in AuditSeverity} else None
    logs = audit_logger.get_logs(limit=limit, offset=offset, event_type=event_enum, severity=severity_enum, user_id=user_id)
    return jsonify(logs)


@app.route("/api/admin/keys")
@login_required
@admin_required
def admin_api_keys():
    keys = api_key_manager.get_api_keys()
    return jsonify({"status": "success", "data": {"keys": keys, "count": len(keys)}})


@app.route("/api/admin/keys", methods=["POST"])
@login_required
@admin_required
def admin_create_api_key():
    data = request.get_json() or {}
    if "name" not in data:
        return jsonify({"status": "error", "message": "Name is required"}), 400
    key_info = api_key_manager.generate_api_key(
        name=data["name"],
        description=data.get("description", ""),
        permissions=data.get("permissions", ["read"]),
        created_by=current_user.username,
        expires_days=data.get("expires_days"),
    )
    return jsonify({"status": "success", "data": key_info}), 201


@app.route("/api/admin/keys/<key_id>", methods=["DELETE"])
@login_required
@admin_required
def admin_revoke_api_key(key_id):
    success = api_key_manager.revoke_api_key(key_id)
    if not success:
        return jsonify({"status": "error", "message": f"API key {key_id} not found"}), 404
    return jsonify({"status": "success", "message": f"API key {key_id} revoked"})


@app.route("/api/process-groups")
@login_required
def api_process_groups():
    return jsonify({"status": "success", "data": process_group_manager.get_groups()})


@app.route("/api/process-groups", methods=["POST"])
@login_required
@admin_required
def api_create_process_group():
    data = request.get_json() or {}
    if "name" not in data:
        return jsonify({"status": "error", "message": "Group name is required"}), 400
    try:
        group_id = process_group_manager.create_group(
            name=data["name"],
            description=data.get("description", ""),
            color=data.get("color", "#0f8d8d"),
            created_by=current_user.username,
        )
        for rule in data.get("rules", []):
            process_group_manager.add_rule(group_id, rule["type"], rule["value"])
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    return jsonify({"status": "success", "group_id": group_id}), 201


@app.route("/api/process-groups/<int:group_id>/kill", methods=["POST"])
@login_required
@admin_required
def api_kill_group_processes(group_id):
    result = process_group_manager.kill_group_processes(group_id, current_user.username)
    return jsonify({"status": "success", "data": result})


@app.route("/api/process-groups/<int:group_id>", methods=["DELETE"])
@login_required
@admin_required
def api_delete_process_group(group_id):
    if not process_group_manager.delete_group(group_id):
        return jsonify({"status": "error", "message": "Failed to delete group"}), 404
    return jsonify({"status": "success"})


@app.route("/api/process-groups/<int:group_id>/processes/<int:pid>", methods=["POST"])
@login_required
@admin_required
def api_add_process_to_group(group_id, pid):
    process_group_manager.add_manual_process(group_id, pid, current_user.username)
    return jsonify({"status": "success"})


@app.route("/api/process-groups/<int:group_id>/processes/<int:pid>", methods=["DELETE"])
@login_required
@admin_required
def api_remove_process_from_group(group_id, pid):
    if not process_group_manager.remove_manual_process(group_id, pid):
        return jsonify({"status": "error", "message": "Failed to remove process"}), 404
    return jsonify({"status": "success"})


@app.route("/api/process-groups/predefined", methods=["POST"])
@login_required
@admin_required
def api_create_predefined_group():
    data = request.get_json() or {}
    if "name" not in data:
        return jsonify({"status": "error", "message": "Predefined group name is required"}), 400
    predefined = next((item for item in process_group_manager.get_predefined_groups() if item["name"] == data["name"]), None)
    if not predefined:
        return jsonify({"status": "error", "message": "Predefined group not found"}), 404
    group_id = process_group_manager.create_predefined_group(predefined, current_user.username)
    return jsonify({"status": "success", "group_id": group_id}), 201


@app.route("/api/security/threats")
@login_required
def api_security_threats():
    hours = max(_safe_int(request.args.get("hours"), 24), 1)
    limit = max(_safe_int(request.args.get("limit"), 100), 1)
    return jsonify({"status": "success", "data": security_monitor.get_recent_threats(hours=hours, limit=limit)})


@app.route("/api/security/statistics")
@login_required
def api_security_statistics():
    return jsonify({"status": "success", "data": security_monitor.get_threat_statistics()})


@app.route("/api/security/threats/<int:threat_id>/resolve", methods=["POST"])
@login_required
@admin_required
def api_resolve_threat(threat_id):
    if not security_monitor.resolve_threat(threat_id, current_user.username):
        return jsonify({"status": "error", "message": "Threat not found"}), 404
    return jsonify({"status": "success"})


@app.route("/api/security/connections")
@login_required
def api_security_connections():
    hours = max(_safe_int(request.args.get("hours"), 1), 1)
    limit = max(_safe_int(request.args.get("limit"), 1000), 1)
    return jsonify({"status": "success", "data": security_monitor.get_connection_logs(hours=hours, limit=limit)})


@app.route("/api/security/monitoring/start", methods=["POST"])
@login_required
@admin_required
def api_start_security_monitoring():
    security_monitor.start_monitoring()
    return jsonify({"status": "success"})


@app.route("/api/security/monitoring/stop", methods=["POST"])
@login_required
@admin_required
def api_stop_security_monitoring():
    security_monitor.stop_monitoring()
    return jsonify({"status": "success"})


@app.route("/api/resource-limits", methods=["GET"])
@login_required
def api_get_resource_limits():
    return jsonify({"status": "success", "data": resource_limiter.get_all_limits()})


@app.route("/api/resource-limits", methods=["POST"])
@login_required
@admin_required
def api_set_resource_limit():
    data = request.get_json() or {}
    required = ["pid", "limit_type", "limit_value", "action"]
    missing = [field for field in required if field not in data]
    if missing:
        return jsonify({"status": "error", "message": f"Missing fields: {', '.join(missing)}"}), 400
    try:
        limit_id = resource_limiter.set_resource_limit(
            pid=int(data["pid"]),
            limit_type=data["limit_type"],
            limit_value=float(data["limit_value"]),
            action=data["action"],
            created_by=current_user.username,
            description=data.get("description", ""),
        )
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    return jsonify({"status": "success", "limit_id": limit_id}), 201


@app.route("/api/resource-limits/<int:limit_id>", methods=["DELETE"])
@login_required
@admin_required
def api_remove_resource_limit(limit_id):
    if not resource_limiter.remove_resource_limit(limit_id):
        return jsonify({"status": "error", "message": "Limit not found"}), 404
    return jsonify({"status": "success"})


@app.route("/api/process/<int:pid>/priority", methods=["POST"])
@login_required
@admin_required
def api_set_process_priority(pid):
    data = request.get_json() or {}
    if "nice_value" not in data:
        return jsonify({"status": "error", "message": "Missing nice_value"}), 400
    nice_value = int(data["nice_value"])
    if nice_value < -20 or nice_value > 19:
        return jsonify({"status": "error", "message": "Nice value must be between -20 and 19"}), 400
    success = resource_limiter.set_process_priority(pid, nice_value, current_user.username)
    if not success:
        return jsonify({"status": "error", "message": "Failed to set process priority"}), 500
    return jsonify({"status": "success"})


@app.route("/api/resource-limits/templates", methods=["GET"])
@login_required
def api_get_templates():
    return jsonify({"status": "success", "data": resource_limiter.get_templates()})


@app.route("/api/resource-limits/templates/<template_name>/apply", methods=["POST"])
@login_required
@admin_required
def api_apply_template(template_name):
    data = request.get_json() or {}
    if "pid" not in data:
        return jsonify({"status": "error", "message": "Missing pid"}), 400
    success = resource_limiter.apply_template(int(data["pid"]), template_name, current_user.username)
    if not success:
        return jsonify({"status": "error", "message": "Failed to apply template"}), 500
    return jsonify({"status": "success"})


@app.route("/api/resource-limits/violations")
@login_required
def api_get_violations():
    hours = max(_safe_int(request.args.get("hours"), 24), 1)
    limit = max(_safe_int(request.args.get("limit"), 100), 1)
    return jsonify({"status": "success", "data": resource_limiter.get_violations(hours=hours, limit=limit)})


@app.route("/api/managed-services", methods=["GET", "POST"])
@login_required
def api_managed_services():
    if request.method == "GET":
        return jsonify({"status": "success", "data": managed_service_manager.list_services()})

    if current_user.role != "admin":
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    data = request.get_json() or {}
    required = ["name", "command"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"status": "error", "message": f"Missing fields: {', '.join(missing)}"}), 400
    try:
        service_id = managed_service_manager.create_service(
            name=data["name"],
            command=data["command"],
            working_directory=data.get("working_directory", ""),
            environment=data.get("environment", {}),
            enabled=bool(data.get("enabled", True)),
            restart_policy=data.get("restart_policy", "on-failure"),
            restart_limit=int(data.get("restart_limit", 3)),
            dependency_ids=data.get("dependency_ids", []),
            created_by=current_user.username,
        )
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    return jsonify({"status": "success", "data": {"id": service_id}}), 201


@app.route("/api/managed-services/<int:service_id>", methods=["GET", "PUT", "DELETE"])
@login_required
def api_managed_service_detail(service_id):
    if request.method == "GET":
        service = managed_service_manager.get_service(service_id)
        if not service:
            return jsonify({"status": "error", "message": "Service not found"}), 404
        return jsonify({"status": "success", "data": service})

    if current_user.role != "admin":
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    if request.method == "DELETE":
        if not managed_service_manager.delete_service(service_id):
            return jsonify({"status": "error", "message": "Service not found"}), 404
        return jsonify({"status": "success"})

    data = request.get_json() or {}
    existing_service = managed_service_manager.get_service(service_id)
    if not existing_service:
        return jsonify({"status": "error", "message": "Service not found"}), 404
    try:
        updated = managed_service_manager.update_service(
            service_id,
            name=data.get("name", existing_service["name"]),
            command=data.get("command", existing_service["command"]),
            working_directory=data.get("working_directory", existing_service.get("working_directory") or ""),
            environment=data.get("environment", existing_service.get("environment") or {}),
            enabled=bool(data.get("enabled", existing_service.get("enabled", True))),
            restart_policy=data.get("restart_policy", existing_service.get("restart_policy", "on-failure")),
            restart_limit=int(data.get("restart_limit", existing_service.get("restart_limit", 3))),
            dependency_ids=data.get("dependency_ids", [dependency["id"] for dependency in existing_service.get("dependencies", [])]),
        )
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    if not updated:
        return jsonify({"status": "error", "message": "Service not found"}), 404
    return jsonify({"status": "success"})


@app.route("/api/managed-services/<int:service_id>/start", methods=["POST"])
@login_required
@admin_required
def api_start_service(service_id):
    try:
        result = managed_service_manager.start_service(service_id, requested_by=current_user.username)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    return jsonify({"status": "success", "data": result})


@app.route("/api/managed-services/<int:service_id>/stop", methods=["POST"])
@login_required
@admin_required
def api_stop_service(service_id):
    try:
        result = managed_service_manager.stop_service(service_id, requested_by=current_user.username)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    return jsonify({"status": "success", "data": result})


@app.route("/api/managed-services/<int:service_id>/restart", methods=["POST"])
@login_required
@admin_required
def api_restart_service(service_id):
    try:
        result = managed_service_manager.restart_service(service_id, requested_by=current_user.username)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    return jsonify({"status": "success", "data": result})


@app.route("/api/managed-services/<int:service_id>/schedules", methods=["GET", "POST"])
@login_required
def api_managed_service_schedules(service_id):
    if request.method == "GET":
        return jsonify({"status": "success", "data": managed_service_manager.get_schedules(service_id)})

    if current_user.role != "admin":
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    data = request.get_json() or {}
    required = ["action", "trigger_type", "trigger_config"]
    missing = [field for field in required if field not in data]
    if missing:
        return jsonify({"status": "error", "message": f"Missing fields: {', '.join(missing)}"}), 400
    try:
        schedule_id = managed_service_manager.add_schedule(
            service_id=service_id,
            action=data["action"],
            trigger_type=data["trigger_type"],
            trigger_config=data["trigger_config"],
            created_by=current_user.username,
        )
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    return jsonify({"status": "success", "data": {"id": schedule_id}}), 201


@app.route("/api/managed-services/<int:service_id>/schedules/<int:schedule_id>", methods=["DELETE"])
@login_required
@admin_required
def api_delete_service_schedule(service_id, schedule_id):
    if not managed_service_manager.remove_schedule(schedule_id):
        return jsonify({"status": "error", "message": "Schedule not found"}), 404
    return jsonify({"status": "success"})


def start_background_services():
    if not metrics_collector.running:
        metrics_collector.start()
    if not security_monitor.monitoring:
        security_monitor.start_monitoring()
    if not enhanced_process_manager.monitoring:
        enhanced_process_manager.start_monitoring()
    if not resource_limiter.monitoring:
        resource_limiter.start_monitoring()
    if not managed_service_manager.running:
        managed_service_manager.start()
    if not notification_manager.running:
        notification_manager.start(port_provider=get_open_ports)


def stop_background_services():
    if metrics_collector.running:
        metrics_collector.stop()
    if security_monitor.monitoring:
        security_monitor.stop_monitoring()
    if enhanced_process_manager.monitoring:
        enhanced_process_manager.stop_monitoring()
    if resource_limiter.monitoring:
        resource_limiter.stop_monitoring()
    if managed_service_manager.running:
        managed_service_manager.stop()
    if notification_manager.running:
        notification_manager.stop()


if __name__ == "__main__":
    start_background_services()
    try:
        app.run(debug=True, host="0.0.0.0", port=5001)
    finally:
        stop_background_services()
