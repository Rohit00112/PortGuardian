from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from utils.api_auth import require_api_key, api_key_manager
from utils.port_scanner import get_open_ports
from utils.process_manager import get_process_info, kill_process
from utils.system_monitor import get_all_system_metrics
from utils.metrics_storage import metrics_storage
from utils.audit_logger import audit_logger, AuditEventType, AuditSeverity
import logging

# Create API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

logger = logging.getLogger('api')

# API Documentation endpoint
@api_bp.route('/docs')
def api_docs():
    """API documentation."""
    return jsonify({
        'name': 'PortGuardian API',
        'version': '1.0.0',
        'description': 'RESTful API for PortGuardian - Port and Process Monitoring Platform',
        'base_url': '/api/v1',
        'authentication': {
            'type': 'API Key',
            'header': 'X-API-Key',
            'format': 'pg_{key_id}_{secret}'
        },
        'endpoints': {
            'system': {
                'GET /system/info': 'Get basic system information',
                'GET /system/health': 'Get comprehensive system health metrics',
                'GET /system/uptime': 'Get system uptime information'
            },
            'ports': {
                'GET /ports': 'Get all open ports and associated processes',
                'GET /ports/{port}': 'Get information about a specific port'
            },
            'processes': {
                'GET /processes': 'Get all running processes',
                'GET /processes/{pid}': 'Get detailed information about a process',
                'DELETE /processes/{pid}': 'Terminate a process (requires write permission)'
            },
            'metrics': {
                'GET /metrics/current': 'Get current system metrics',
                'GET /metrics/history': 'Get historical metrics data',
                'GET /metrics/cpu': 'Get CPU metrics',
                'GET /metrics/memory': 'Get memory metrics',
                'GET /metrics/disk': 'Get disk metrics',
                'GET /metrics/network': 'Get network metrics'
            },
            'audit': {
                'GET /audit/logs': 'Get audit logs (requires admin permission)',
                'GET /audit/stats': 'Get audit statistics'
            },
            'management': {
                'GET /keys': 'List API keys (requires admin permission)',
                'POST /keys': 'Create new API key (requires admin permission)',
                'DELETE /keys/{key_id}': 'Revoke API key (requires admin permission)'
            }
        },
        'permissions': {
            'read': 'Read-only access to system information',
            'write': 'Read and write access (can terminate processes)',
            'admin': 'Full administrative access'
        }
    })

# System Information Endpoints
@api_bp.route('/system/info')
@require_api_key(['read'])
def get_system_info():
    """Get basic system information."""
    try:
        metrics = get_all_system_metrics()
        return jsonify({
            'status': 'success',
            'data': {
                'system_info': metrics.get('system_info', {}),
                'uptime_info': metrics.get('uptime_info', {}),
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Error getting system info: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/system/health')
@require_api_key(['read'])
def get_system_health():
    """Get comprehensive system health metrics."""
    try:
        metrics = get_all_system_metrics()
        return jsonify({
            'status': 'success',
            'data': metrics
        })
    except Exception as e:
        logger.error(f"Error getting system health: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/system/uptime')
@require_api_key(['read'])
def get_system_uptime():
    """Get system uptime information."""
    try:
        metrics = get_all_system_metrics()
        return jsonify({
            'status': 'success',
            'data': metrics.get('uptime_info', {})
        })
    except Exception as e:
        logger.error(f"Error getting system uptime: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Port Information Endpoints
@api_bp.route('/ports')
@require_api_key(['read'])
def get_ports():
    """Get all open ports and associated processes."""
    try:
        ports = get_open_ports()
        return jsonify({
            'status': 'success',
            'data': {
                'ports': ports,
                'count': len(ports),
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Error getting ports: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/ports/<int:port>')
@require_api_key(['read'])
def get_port_info(port):
    """Get information about a specific port."""
    try:
        ports = get_open_ports()
        port_info = next((p for p in ports if p['port'] == port), None)
        
        if not port_info:
            return jsonify({
                'status': 'error',
                'message': f'Port {port} not found or not listening'
            }), 404
        
        return jsonify({
            'status': 'success',
            'data': port_info
        })
    except Exception as e:
        logger.error(f"Error getting port info: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Process Information Endpoints
@api_bp.route('/processes')
@require_api_key(['read'])
def get_processes():
    """Get all running processes."""
    try:
        ports = get_open_ports()
        processes = {}
        
        for port in ports:
            if port['pid'] != 'N/A':
                pid = port['pid']
                if pid not in processes:
                    process_info = get_process_info(pid)
                    if process_info:
                        processes[pid] = process_info
        
        return jsonify({
            'status': 'success',
            'data': {
                'processes': list(processes.values()),
                'count': len(processes),
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Error getting processes: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/processes/<int:pid>')
@require_api_key(['read'])
def get_process_detail(pid):
    """Get detailed information about a process."""
    try:
        process_info = get_process_info(pid)
        
        if not process_info:
            return jsonify({
                'status': 'error',
                'message': f'Process with PID {pid} not found'
            }), 404
        
        return jsonify({
            'status': 'success',
            'data': process_info
        })
    except Exception as e:
        logger.error(f"Error getting process detail: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/processes/<int:pid>', methods=['DELETE'])
@require_api_key(['write'])
def terminate_process(pid):
    """Terminate a process."""
    try:
        # Get process info before killing for audit
        process_info = get_process_info(pid)
        process_name = process_info.get('name', 'Unknown') if process_info else 'Unknown'
        
        result = kill_process(pid, user_id=f"api_key_{request.api_key_info['key_id']}")
        
        # Log the API action
        audit_logger.log_event(
            event_type=AuditEventType.PROCESS_KILL,
            severity=AuditSeverity.HIGH,
            user_id=request.api_key_info['key_id'],
            username=f"api_{request.api_key_info['name']}",
            ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
            user_agent=request.headers.get('User-Agent', ''),
            resource='process_management',
            action=f'api_kill_process_{pid}',
            details={
                'pid': pid,
                'process_name': process_name,
                'api_key_name': request.api_key_info['name']
            },
            success=result['success'],
            error_message=result['message'] if not result['success'] else None
        )
        
        if result['success']:
            return jsonify({
                'status': 'success',
                'message': result['message']
            })
        else:
            return jsonify({
                'status': 'error',
                'message': result['message']
            }), 400
    
    except Exception as e:
        logger.error(f"Error terminating process: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Metrics Endpoints
@api_bp.route('/metrics/current')
@require_api_key(['read'])
def get_current_metrics():
    """Get current system metrics."""
    try:
        metrics = get_all_system_metrics()
        return jsonify({
            'status': 'success',
            'data': {
                'cpu': metrics.get('cpu_info', {}),
                'memory': metrics.get('memory_info', {}),
                'disk': metrics.get('disk_info', {}),
                'network': metrics.get('network_info', {}),
                'load': metrics.get('load_info', {}),
                'timestamp': metrics.get('timestamp')
            }
        })
    except Exception as e:
        logger.error(f"Error getting current metrics: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/metrics/history')
@require_api_key(['read'])
def get_metrics_history():
    """Get historical metrics data."""
    try:
        metric_type = request.args.get('type')
        metric_name = request.args.get('name')
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 1000))
        
        start_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        metrics = metrics_storage.get_metrics(
            metric_type=metric_type,
            metric_name=metric_name,
            start_time=start_time,
            limit=limit
        )
        
        return jsonify({
            'status': 'success',
            'data': {
                'metrics': metrics,
                'count': len(metrics),
                'filters': {
                    'type': metric_type,
                    'name': metric_name,
                    'hours': hours,
                    'limit': limit
                }
            }
        })
    except Exception as e:
        logger.error(f"Error getting metrics history: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Audit Endpoints
@api_bp.route('/audit/logs')
@require_api_key(['admin'])
def get_audit_logs():
    """Get audit logs."""
    try:
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        logs = audit_logger.get_logs(limit=limit, offset=offset)
        
        return jsonify({
            'status': 'success',
            'data': {
                'logs': logs,
                'count': len(logs),
                'pagination': {
                    'limit': limit,
                    'offset': offset
                }
            }
        })
    except Exception as e:
        logger.error(f"Error getting audit logs: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/audit/stats')
@require_api_key(['read'])
def get_audit_stats():
    """Get audit statistics."""
    try:
        stats = audit_logger.get_log_statistics()
        return jsonify({
            'status': 'success',
            'data': stats
        })
    except Exception as e:
        logger.error(f"Error getting audit stats: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# API Key Management Endpoints
@api_bp.route('/keys')
@require_api_key(['admin'])
def list_api_keys():
    """List all API keys."""
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
        logger.error(f"Error listing API keys: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/keys', methods=['POST'])
@require_api_key(['admin'])
def create_api_key():
    """Create a new API key."""
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
            created_by=f"api_{request.api_key_info['name']}",
            expires_days=data.get('expires_days')
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

@api_bp.route('/keys/<key_id>', methods=['DELETE'])
@require_api_key(['admin'])
def revoke_api_key(key_id):
    """Revoke an API key."""
    try:
        success = api_key_manager.revoke_api_key(key_id)
        
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
