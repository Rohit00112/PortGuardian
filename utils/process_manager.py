import psutil
import os
import signal
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='process_manager.log',
    filemode='a'
)
logger = logging.getLogger('process_manager')

def get_process_info(pid):
    """Get detailed information about a process."""
    try:
        process = psutil.Process(pid)

        # Basic process info
        info = {
            'pid': pid,
            'name': process.name(),
            'status': process.status(),
            'username': process.username(),
            'cpu_percent': process.cpu_percent(interval=0.1),
            'memory_percent': process.memory_percent(),
            'create_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
            'command': ' '.join(process.cmdline()),
            'cwd': process.cwd(),
            'parent': None,
            'children': [],
            'connections': []
        }

        # Get parent process info if available
        try:
            parent = process.parent()
            if parent:
                info['parent'] = {
                    'pid': parent.pid,
                    'name': parent.name()
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Get children processes
        try:
            children = process.children()
            for child in children:
                info['children'].append({
                    'pid': child.pid,
                    'name': child.name()
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Get network connections
        try:
            connections = process.connections()
            for conn in connections:
                conn_info = {
                    'fd': conn.fd,
                    'family': conn.family,
                    'type': conn.type,
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    'status': conn.status
                }
                info['connections'].append(conn_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Just log the error but don't fail
            logger.warning(f"Access denied to connections for process with PID {pid}")
            pass

        return info

    except psutil.NoSuchProcess:
        logger.error(f"Process with PID {pid} not found")
        return None
    except psutil.AccessDenied:
        logger.error(f"Access denied to process with PID {pid}")
        return {
            'pid': pid,
            'name': "Access Denied",
            'status': "unknown",
            'username': "unknown",
            'cpu_percent': 0,
            'memory_percent': 0,
            'create_time': "unknown",
            'command': "Access denied - this application requires elevated privileges on macOS",
            'cwd': "unknown",
            'parent': None,
            'children': [],
            'connections': [],
            'error': "Access denied to this process. On macOS, this application requires elevated privileges to access detailed process information."
        }
    except Exception as e:
        logger.error(f"Error getting process info for PID {pid}: {str(e)}")
        return {
            'pid': pid,
            'name': "Error",
            'status': "unknown",
            'username': "unknown",
            'cpu_percent': 0,
            'memory_percent': 0,
            'create_time': "unknown",
            'command': f"Error: {str(e)}",
            'cwd': "unknown",
            'parent': None,
            'children': [],
            'connections': [],
            'error': str(e)
        }

def kill_process(pid, user_id="system"):
    """Kill a process by PID."""
    try:
        process = psutil.Process(pid)
        process_name = process.name()

        # Log the kill attempt
        logger.info(f"User {user_id} attempting to kill process {pid} ({process_name})")

        # Try to terminate the process gracefully first
        process.terminate()

        # Wait for the process to terminate
        gone, alive = psutil.wait_procs([process], timeout=3)

        # If the process is still alive, kill it forcefully
        if process in alive:
            logger.warning(f"Process {pid} did not terminate gracefully, forcing kill")
            process.kill()

        # Log successful termination
        logger.info(f"Process {pid} ({process_name}) successfully terminated by user {user_id}")

        return {
            'success': True,
            'message': f"Process {pid} ({process_name}) successfully terminated"
        }

    except psutil.NoSuchProcess:
        logger.error(f"Process with PID {pid} not found")
        return {
            'success': False,
            'message': f"Process with PID {pid} not found"
        }
    except psutil.AccessDenied:
        logger.error(f"Access denied to kill process with PID {pid}")
        return {
            'success': False,
            'message': f"Access denied to kill process with PID {pid}"
        }
    except Exception as e:
        logger.error(f"Error killing process {pid}: {str(e)}")
        return {
            'success': False,
            'message': f"Error: {str(e)}"
        }
