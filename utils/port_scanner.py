import socket
import psutil
import time
from datetime import datetime

def get_process_name(pid):
    """Get process name from pid."""
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "N/A"

def get_process_command(pid):
    """Get command used to start the process."""
    try:
        process = psutil.Process(pid)
        return " ".join(process.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "N/A"

def get_process_start_time(pid):
    """Get process start time."""
    try:
        process = psutil.Process(pid)
        return datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "N/A"

def get_open_ports():
    """Get all open ports and their associated processes."""
    open_ports = []

    try:
        # Get all network connections
        connections = psutil.net_connections(kind='inet')

        for conn in connections:
            if conn.status == 'LISTEN':
                status = 'LISTENING'
            else:
                status = conn.status

            # Get local address details
            if conn.laddr:
                ip, port = conn.laddr
            else:
                ip, port = 'N/A', 'N/A'

            # Get process details if available
            if conn.pid:
                pid = conn.pid
                process_name = get_process_name(pid)
                command = get_process_command(pid)
                start_time = get_process_start_time(pid)
            else:
                pid = 'N/A'
                process_name = 'N/A'
                command = 'N/A'
                start_time = 'N/A'

            # Determine protocol (TCP/UDP)
            if conn.type == socket.SOCK_STREAM:
                protocol = 'TCP'
            elif conn.type == socket.SOCK_DGRAM:
                protocol = 'UDP'
            else:
                protocol = 'UNKNOWN'

            open_ports.append({
                'port': port,
                'protocol': protocol,
                'status': status,
                'pid': pid,
                'process_name': process_name,
                'command': command,
                'start_time': start_time,
                'ip': ip
            })
    except psutil.AccessDenied:
        # If we don't have permission, add a dummy entry explaining the issue
        open_ports.append({
            'port': 'N/A',
            'protocol': 'N/A',
            'status': 'N/A',
            'pid': 'N/A',
            'process_name': 'Permission Denied',
            'command': 'This application requires elevated privileges to access process information on macOS',
            'start_time': 'N/A',
            'ip': 'N/A'
        })
    except Exception as e:
        # Handle any other exceptions
        open_ports.append({
            'port': 'N/A',
            'protocol': 'N/A',
            'status': 'N/A',
            'pid': 'N/A',
            'process_name': 'Error',
            'command': f'Error retrieving port information: {str(e)}',
            'start_time': 'N/A',
            'ip': 'N/A'
        })

    return open_ports
