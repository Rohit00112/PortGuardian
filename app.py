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
    result = kill_process(pid, user_id=current_user.username)

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
            return redirect(url_for('index'))

        flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout."""
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

@app.route('/export')
@login_required
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
    # Start the metrics collector
    metrics_collector.start()

    try:
        app.run(debug=True, host='0.0.0.0', port=5001)
    finally:
        # Stop the metrics collector when the app shuts down
        metrics_collector.stop()
