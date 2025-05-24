from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import logging
from datetime import datetime

from utils.port_scanner import get_open_ports
from utils.process_manager import get_process_info, kill_process
from utils.audit_logger import audit_logger, AuditEventType, AuditSeverity
from utils.audit_decorators import audit_action, audit_login_attempt, audit_logout, audit_process_kill
from utils.system_monitor import get_all_system_metrics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log',
    filemode='a'
)
logger = logging.getLogger('portguardian')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simple user model for authentication
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

# For demo purposes, we'll use a simple dictionary to store users
# In a real application, you would use a database
users = {
    1: User(1, 'admin', generate_password_hash('admin'))
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

# Routes
@app.route('/')
@login_required
@audit_action(AuditEventType.PAGE_ACCESS, AuditSeverity.LOW, resource="dashboard", action="view_dashboard")
def index():
    """Home dashboard showing all open ports and processes."""
    try:
        ports = get_open_ports()
        permission_error = False
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        ports = []
        permission_error = True

    return render_template('index.html', ports=ports, permission_error=permission_error)

@app.route('/process/<int:pid>')
@login_required
@audit_action(AuditEventType.PROCESS_VIEW, AuditSeverity.LOW, resource="process", action="view_process_details")
def process_detail(pid):
    """Detailed view of a specific process."""
    process_info = get_process_info(pid)
    if not process_info:
        flash('Process not found', 'danger')
        return redirect(url_for('index'))
    return render_template('process_detail.html', process=process_info)

@app.route('/kill/<int:pid>', methods=['POST'])
@login_required
def kill_process_route(pid):
    """Kill a process by PID."""
    # Get process name before killing for audit log
    process_info = get_process_info(pid)
    process_name = process_info.get('name', 'Unknown') if process_info else 'Unknown'

    result = kill_process(pid, user_id=current_user.username)

    # Audit the process kill attempt
    audit_process_kill(
        pid=pid,
        process_name=process_name,
        success=result['success'],
        error_message=result['message'] if not result['success'] else None
    )

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(result)

    if result['success']:
        flash(result['message'], 'success')
    else:
        flash(result['message'], 'danger')

    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Find user by username
        user = next((u for u in users.values() if u.username == username), None)

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            logger.info(f"User {username} logged in")

            # Audit successful login
            audit_login_attempt(success=True, username=username)

            return redirect(url_for('index'))

        # Audit failed login attempt
        audit_login_attempt(success=False, username=username, error_message="Invalid credentials")

        flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout."""
    username = current_user.username

    # Audit logout
    audit_logout(username)

    logout_user()
    return redirect(url_for('login'))

@app.route('/api/ports')
@login_required
def api_ports():
    """API endpoint to get all open ports as JSON."""
    ports = get_open_ports()
    return jsonify(ports)

@app.route('/api/process/<int:pid>')
@login_required
def api_process(pid):
    """API endpoint to get process details as JSON."""
    process_info = get_process_info(pid)
    if not process_info:
        return jsonify({'error': 'Process not found'}), 404
    return jsonify(process_info)


@app.route('/api/save-theme', methods=['POST'])
@login_required
def save_theme():
    """Save user theme preference."""
    try:
        theme = request.json.get('theme', 'light')
        # In a real application, you would save this to a database
        # For now, we'll just return success
        return jsonify({'success': True, 'theme': theme})
    except Exception as e:
        logger.error(f"Error saving theme preference: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/audit-logs')
@login_required
@audit_action(AuditEventType.PAGE_ACCESS, AuditSeverity.MEDIUM, resource="audit", action="view_audit_logs")
def audit_logs():
    """View audit logs."""
    try:
        # Get filter parameters
        event_type = request.args.get('event_type')
        severity = request.args.get('severity')
        user_id = request.args.get('user_id')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        # Convert string parameters to enum values
        event_type_enum = None
        if event_type:
            try:
                event_type_enum = AuditEventType(event_type)
            except ValueError:
                pass

        severity_enum = None
        if severity:
            try:
                severity_enum = AuditSeverity(severity)
            except ValueError:
                pass

        # Get logs with pagination
        offset = (page - 1) * per_page
        logs = audit_logger.get_logs(
            limit=per_page,
            offset=offset,
            event_type=event_type_enum,
            severity=severity_enum,
            user_id=user_id
        )

        # Get statistics
        stats = audit_logger.get_log_statistics()

        return render_template('audit_logs.html',
                             logs=logs,
                             stats=stats,
                             page=page,
                             per_page=per_page,
                             event_types=[e.value for e in AuditEventType],
                             severities=[s.value for s in AuditSeverity])

    except Exception as e:
        logger.error(f"Error in audit logs route: {str(e)}")
        flash(f"Error retrieving audit logs: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/api/audit-logs')
@login_required
@audit_action(AuditEventType.API_ACCESS, AuditSeverity.MEDIUM, resource="audit_api", action="get_audit_logs")
def api_audit_logs():
    """API endpoint to get audit logs as JSON."""
    try:
        # Get filter parameters
        event_type = request.args.get('event_type')
        severity = request.args.get('severity')
        user_id = request.args.get('user_id')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))

        # Convert string parameters to enum values
        event_type_enum = None
        if event_type:
            try:
                event_type_enum = AuditEventType(event_type)
            except ValueError:
                pass

        severity_enum = None
        if severity:
            try:
                severity_enum = AuditSeverity(severity)
            except ValueError:
                pass

        logs = audit_logger.get_logs(
            limit=limit,
            offset=offset,
            event_type=event_type_enum,
            severity=severity_enum,
            user_id=user_id
        )

        return jsonify(logs)

    except Exception as e:
        logger.error(f"Error in audit logs API: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/export-audit-logs')
@login_required
@audit_action(AuditEventType.DATA_EXPORT, AuditSeverity.HIGH, resource="audit", action="export_audit_logs")
def export_audit_logs():
    """Export audit logs."""
    try:
        format_type = request.args.get('format', 'json')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        exported_data = audit_logger.export_logs(
            format=format_type,
            start_date=start_date,
            end_date=end_date
        )

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"audit_logs_{timestamp}.{format_type}"

        if format_type.lower() == 'json':
            return jsonify({
                'filename': filename,
                'data': exported_data,
                'timestamp': timestamp
            })
        else:
            # For CSV, return as text
            from flask import Response
            return Response(
                exported_data,
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )

    except Exception as e:
        logger.error(f"Error exporting audit logs: {str(e)}")
        return jsonify({'error': str(e)}), 500
@app.route('/system-health')
@login_required
def system_health():
    """System health dashboard showing CPU, memory, disk, and network metrics."""
    try:
        metrics = get_all_system_metrics()

        # Check if any of the metrics have errors
        has_errors = False
        error_messages = []

        for key, value in metrics.items():
            if isinstance(value, dict) and 'error' in value:
                has_errors = True
                error_messages.append(f"{key}: {value['error']}")

        if has_errors:
            for message in error_messages:
                flash(message, 'warning')

        return render_template('system_health.html', metrics=metrics)
    except Exception as e:
        logger.error(f"Error in system health dashboard: {str(e)}")
        flash(f"Error retrieving system metrics: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/api/system-health')
@login_required
def api_system_health():
    """API endpoint to get system health metrics as JSON."""
    try:
        metrics = get_all_system_metrics()
        return jsonify(metrics)
    except Exception as e:
        logger.error(f"Error in system health API: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/export')
@login_required
@audit_action(AuditEventType.DATA_EXPORT, AuditSeverity.MEDIUM, resource="system_data", action="export_port_data")
def export_data():
    """Export port and process data as JSON."""
    ports = get_open_ports()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"port_data_{timestamp}.json"

    # In a real application, you would save this file and provide a download link
    # For simplicity, we'll just return the JSON
    return jsonify({
        'timestamp': timestamp,
        'ports': ports
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
