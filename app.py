from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import logging
from datetime import datetime

from utils.port_scanner import get_open_ports
from utils.process_manager import get_process_info, kill_process
from utils.metrics_storage import metrics_storage
from utils.metrics_collector import metrics_collector
from utils.api_auth import api_key_manager
from api.endpoints import api_bp
from utils.audit_logger import audit_logger, AuditEventType, AuditSeverity
from utils.audit_decorators import audit_action, audit_login_attempt, audit_logout, audit_process_kill
from utils.system_monitor import get_all_system_metrics
from utils.process_groups import process_group_manager
from utils.security_monitor import security_monitor

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

# Register API blueprint
app.register_blueprint(api_bp)

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

@app.route('/charts')
@login_required
def charts():
    """Real-time charts dashboard."""
    return render_template('charts.html')

@app.route('/api/chart-data/<metric_type>')
@login_required
def api_chart_data(metric_type):
    """API endpoint to get chart data for specific metric type."""
    try:
        hours = int(request.args.get('hours', 24))

        # Define metric names for each type
        metric_mappings = {
            'cpu': ['overall_percent', 'core_0_percent', 'core_1_percent'],
            'memory': ['virtual_percent', 'swap_percent'],
            'load': ['load_1_min', 'load_5_min', 'load_15_min'],
            'disk': [],  # Will be populated dynamically
            'network': []  # Will be populated dynamically
        }

        # For disk and network, get available metrics dynamically
        if metric_type == 'disk':
            # Get recent disk metrics to determine available partitions
            recent_metrics = metrics_storage.get_metrics(metric_type='disk', limit=10)
            disk_metrics = set()
            for metric in recent_metrics:
                if metric['metric_name'].endswith('_percent'):
                    disk_metrics.add(metric['metric_name'])
            metric_mappings['disk'] = list(disk_metrics)[:5]  # Limit to 5 partitions

        elif metric_type == 'network':
            # Get recent network metrics to determine available interfaces
            recent_metrics = metrics_storage.get_metrics(metric_type='network', limit=10)
            network_metrics = set()
            for metric in recent_metrics:
                if 'bytes_sent' in metric['metric_name']:
                    interface = metric['metric_name'].replace('_bytes_sent', '')
                    network_metrics.add(f"{interface}_bytes_sent")
                    network_metrics.add(f"{interface}_bytes_recv")
            metric_mappings['network'] = list(network_metrics)[:6]  # Limit to 3 interfaces (sent/recv)

        metric_names = metric_mappings.get(metric_type, [])

        if not metric_names:
            return jsonify({'error': f'No metrics available for type: {metric_type}'}), 404

        chart_data = metrics_storage.get_chart_data(metric_type, metric_names, hours)

        return jsonify(chart_data)

    except Exception as e:
        logger.error(f"Error getting chart data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/metrics/collect')
@login_required
def api_collect_metrics():
    """API endpoint to manually trigger metrics collection."""
    try:
        metrics_collector.collect_now()
        return jsonify({'success': True, 'message': 'Metrics collected successfully'})
    except Exception as e:
        logger.error(f"Error collecting metrics: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

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


@app.route('/api-management')
@login_required
@audit_action(AuditEventType.PAGE_ACCESS, AuditSeverity.MEDIUM, resource="api_management", action="view_api_management")
def api_management():
    """API management interface."""
    return render_template('api_management.html')

@app.route('/api/admin/keys')
@login_required
def admin_api_keys():
    """Admin endpoint to manage API keys (web interface)."""
    try:
        keys = api_key_manager.get_api_keys()
        return jsonify({
            'status': 'success',
            'data': {
                'keys': keys,
                'count': len(keys)
            }
        })
    except Exception as e:
        logger.error(f"Error getting API keys: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/admin/keys', methods=['POST'])
@login_required
def admin_create_api_key():
    """Admin endpoint to create API keys (web interface)."""
    try:
        data = request.get_json()

        if not data or 'name' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Name is required'
            }), 400

        key_info = api_key_manager.generate_api_key(
            name=data['name'],
            description=data.get('description', ''),
            permissions=data.get('permissions', ['read']),
            created_by=current_user.username,
            expires_days=data.get('expires_days')
        )

        # Audit the API key creation
        audit_logger.log_event(
            event_type=AuditEventType.API_ACCESS,
            severity=AuditSeverity.HIGH,
            user_id=str(current_user.id),
            username=current_user.username,
            ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
            user_agent=request.headers.get('User-Agent', ''),
            resource='api_key_management',
            action='create_api_key',
            details={
                'key_name': data['name'],
                'permissions': data.get('permissions', ['read'])
            },
            success=True
        )

        return jsonify({
            'status': 'success',
            'data': key_info
        }), 201

    except Exception as e:
        logger.error(f"Error creating API key: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/admin/keys/<key_id>', methods=['DELETE'])
@login_required
def admin_revoke_api_key(key_id):
    """Admin endpoint to revoke API keys (web interface)."""
    try:
        success = api_key_manager.revoke_api_key(key_id)

        # Audit the API key revocation
        audit_logger.log_event(
            event_type=AuditEventType.API_ACCESS,
            severity=AuditSeverity.HIGH,
            user_id=str(current_user.id),
            username=current_user.username,
            ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
            user_agent=request.headers.get('User-Agent', ''),
            resource='api_key_management',
            action='revoke_api_key',
            details={
                'key_id': key_id
            },
            success=success
        )

        if success:
            return jsonify({
                'status': 'success',
                'message': f'API key {key_id} has been revoked'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'API key {key_id} not found'
            }), 404

    except Exception as e:
        logger.error(f"Error revoking API key: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/export')
@login_required
@audit_action(AuditEventType.DATA_EXPORT, AuditSeverity.MEDIUM, resource="system_data", action="export_port_data")
def export_data():
    """Export port and process data as JSON."""
    ports = get_open_ports()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # In a real application, you would save this file and provide a download link
    # For simplicity, we'll just return the JSON
    return jsonify({
        'timestamp': timestamp,
        'ports': ports
    })

@app.route('/process-groups')
@login_required
@audit_action(AuditEventType.PAGE_ACCESS, AuditSeverity.LOW, resource="process_groups", action="view_process_groups")
def process_groups():
    """Process groups management page."""
    try:
        groups = process_group_manager.get_groups()
        predefined = process_group_manager.get_predefined_groups()
        return render_template('process_groups.html', groups=groups, predefined=predefined)
    except Exception as e:
        logger.error(f"Error in process groups route: {str(e)}")
        flash(f"Error retrieving process groups: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/api/process-groups')
@login_required
def api_process_groups():
    """API endpoint to get all process groups."""
    try:
        groups = process_group_manager.get_groups()
        return jsonify({'status': 'success', 'data': groups})
    except Exception as e:
        logger.error(f"Error in process groups API: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/process-groups', methods=['POST'])
@login_required
@audit_action(AuditEventType.PROCESS_MANAGEMENT, AuditSeverity.MEDIUM, resource="process_groups", action="create_group")
def api_create_process_group():
    """API endpoint to create a new process group."""
    try:
        data = request.get_json()

        if not data or 'name' not in data:
            return jsonify({'status': 'error', 'message': 'Group name is required'}), 400

        group_id = process_group_manager.create_group(
            name=data['name'],
            description=data.get('description', ''),
            color=data.get('color', '#007bff'),
            created_by=current_user.username
        )

        # Add rules if provided
        if 'rules' in data:
            for rule in data['rules']:
                process_group_manager.add_rule(group_id, rule['type'], rule['value'])

        return jsonify({
            'status': 'success',
            'message': f'Process group "{data["name"]}" created successfully',
            'group_id': group_id
        }), 201

    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Error creating process group: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/process-groups/<int:group_id>/kill', methods=['POST'])
@login_required
@audit_action(AuditEventType.PROCESS_KILL, AuditSeverity.HIGH, resource="process_groups", action="kill_group_processes")
def api_kill_group_processes(group_id):
    """API endpoint to kill all processes in a group."""
    try:
        result = process_group_manager.kill_group_processes(group_id, current_user.username)

        # Audit the group kill operation
        audit_logger.log_event(
            event_type=AuditEventType.PROCESS_KILL,
            severity=AuditSeverity.HIGH,
            user_id=str(current_user.id),
            username=current_user.username,
            ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
            user_agent=request.headers.get('User-Agent', ''),
            resource='process_group',
            action='kill_group_processes',
            details={
                'group_id': group_id,
                'total_processes': result['total'],
                'successful_kills': result['successful'],
                'failed_kills': result['failed']
            },
            success=result['failed'] == 0
        )

        return jsonify({
            'status': 'success',
            'message': f"Group operation completed: {result['successful']} processes killed, {result['failed']} failed",
            'data': result
        })

    except Exception as e:
        logger.error(f"Error killing group processes: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/process-groups/<int:group_id>', methods=['DELETE'])
@login_required
@audit_action(AuditEventType.PROCESS_MANAGEMENT, AuditSeverity.MEDIUM, resource="process_groups", action="delete_group")
def api_delete_process_group(group_id):
    """API endpoint to delete a process group."""
    try:
        success = process_group_manager.delete_group(group_id)

        if success:
            return jsonify({
                'status': 'success',
                'message': f'Process group {group_id} deleted successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to delete process group {group_id}'
            }), 500

    except Exception as e:
        logger.error(f"Error deleting process group: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/process-groups/<int:group_id>/processes/<int:pid>', methods=['POST'])
@login_required
def api_add_process_to_group(group_id, pid):
    """API endpoint to manually add a process to a group."""
    try:
        success = process_group_manager.add_manual_process(group_id, pid, current_user.username)

        if success:
            return jsonify({
                'status': 'success',
                'message': f'Process {pid} added to group {group_id}'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to add process {pid} to group {group_id}'
            }), 500

    except Exception as e:
        logger.error(f"Error adding process to group: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/process-groups/<int:group_id>/processes/<int:pid>', methods=['DELETE'])
@login_required
def api_remove_process_from_group(group_id, pid):
    """API endpoint to remove a manually added process from a group."""
    try:
        success = process_group_manager.remove_manual_process(group_id, pid)

        if success:
            return jsonify({
                'status': 'success',
                'message': f'Process {pid} removed from group {group_id}'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to remove process {pid} from group {group_id}'
            }), 500

    except Exception as e:
        logger.error(f"Error removing process from group: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/process-groups/predefined', methods=['POST'])
@login_required
def api_create_predefined_group():
    """API endpoint to create a predefined process group."""
    try:
        data = request.get_json()

        if not data or 'name' not in data:
            return jsonify({'status': 'error', 'message': 'Predefined group name is required'}), 400

        predefined_groups = process_group_manager.get_predefined_groups()
        selected_group = next((g for g in predefined_groups if g['name'] == data['name']), None)

        if not selected_group:
            return jsonify({'status': 'error', 'message': 'Predefined group not found'}), 404

        group_id = process_group_manager.create_predefined_group(selected_group, current_user.username)

        return jsonify({
            'status': 'success',
            'message': f'Predefined group "{selected_group["name"]}" created successfully',
            'group_id': group_id
        }), 201

    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Error creating predefined group: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/security-dashboard')
@login_required
@audit_action(AuditEventType.PAGE_ACCESS, AuditSeverity.MEDIUM, resource="security", action="view_security_dashboard")
def security_dashboard():
    """Security monitoring dashboard."""
    try:
        threats = security_monitor.get_recent_threats(hours=24, limit=50)
        stats = security_monitor.get_threat_statistics()
        return render_template('security_dashboard.html', threats=threats, stats=stats)
    except Exception as e:
        logger.error(f"Error in security dashboard route: {str(e)}")
        flash(f"Error retrieving security data: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/api/security/threats')
@login_required
def api_security_threats():
    """API endpoint to get recent threats."""
    try:
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 100))
        threats = security_monitor.get_recent_threats(hours=hours, limit=limit)
        return jsonify({'status': 'success', 'data': threats})
    except Exception as e:
        logger.error(f"Error in security threats API: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/security/statistics')
@login_required
def api_security_statistics():
    """API endpoint to get security statistics."""
    try:
        stats = security_monitor.get_threat_statistics()
        return jsonify({'status': 'success', 'data': stats})
    except Exception as e:
        logger.error(f"Error in security statistics API: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/security/threats/<int:threat_id>/resolve', methods=['POST'])
@login_required
@audit_action(AuditEventType.SECURITY_VIOLATION, AuditSeverity.MEDIUM, resource="security", action="resolve_threat")
def api_resolve_threat(threat_id):
    """API endpoint to resolve a threat."""
    try:
        success = security_monitor.resolve_threat(threat_id, current_user.username)

        if success:
            return jsonify({
                'status': 'success',
                'message': f'Threat {threat_id} marked as resolved'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to resolve threat {threat_id}'
            }), 404

    except Exception as e:
        logger.error(f"Error resolving threat: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/security/connections')
@login_required
def api_security_connections():
    """API endpoint to get recent connection logs."""
    try:
        hours = int(request.args.get('hours', 1))
        limit = int(request.args.get('limit', 1000))
        connections = security_monitor.get_connection_logs(hours=hours, limit=limit)
        return jsonify({'status': 'success', 'data': connections})
    except Exception as e:
        logger.error(f"Error in security connections API: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/security/monitoring/start', methods=['POST'])
@login_required
@audit_action(AuditEventType.SECURITY_VIOLATION, AuditSeverity.HIGH, resource="security", action="start_monitoring")
def api_start_security_monitoring():
    """API endpoint to start security monitoring."""
    try:
        security_monitor.start_monitoring()
        return jsonify({
            'status': 'success',
            'message': 'Security monitoring started'
        })
    except Exception as e:
        logger.error(f"Error starting security monitoring: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/security/monitoring/stop', methods=['POST'])
@login_required
@audit_action(AuditEventType.SECURITY_VIOLATION, AuditSeverity.HIGH, resource="security", action="stop_monitoring")
def api_stop_security_monitoring():
    """API endpoint to stop security monitoring."""
    try:
        security_monitor.stop_monitoring()
        return jsonify({
            'status': 'success',
            'message': 'Security monitoring stopped'
        })
    except Exception as e:
        logger.error(f"Error stopping security monitoring: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    # Start the metrics collector
    metrics_collector.start()

    # Start the security monitor
    security_monitor.start_monitoring()

    try:
        app.run(debug=True, host='0.0.0.0', port=5001)
    finally:
        # Stop the metrics collector when the app shuts down
        metrics_collector.stop()

        # Stop the security monitor when the app shuts down
        security_monitor.stop_monitoring()
