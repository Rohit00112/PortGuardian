import psutil
import platform
import datetime
import logging
from datetime import timedelta

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='system_monitor.log',
    filemode='a'
)
logger = logging.getLogger('system_monitor')

def get_system_info():
    """Get basic system information."""
    try:
        info = {
            'system': platform.system(),
            'node': platform.node(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
        }
        return info
    except Exception as e:
        logger.error(f"Error getting system info: {str(e)}")
        return {
            'error': f"Failed to retrieve system information: {str(e)}"
        }

def get_cpu_info():
    """Get CPU information and usage."""
    try:
        cpu_info = {
            'physical_cores': psutil.cpu_count(logical=False),
            'total_cores': psutil.cpu_count(logical=True),
            'cpu_percent': psutil.cpu_percent(interval=1, percpu=True),
            'cpu_freq': {
                'current': psutil.cpu_freq().current if psutil.cpu_freq() else None,
                'min': psutil.cpu_freq().min if psutil.cpu_freq() and hasattr(psutil.cpu_freq(), 'min') else None,
                'max': psutil.cpu_freq().max if psutil.cpu_freq() and hasattr(psutil.cpu_freq(), 'max') else None
            },
            'cpu_stats': dict(psutil.cpu_stats()._asdict()) if hasattr(psutil, 'cpu_stats') else {},
            'cpu_times_percent': dict(psutil.cpu_times_percent()._asdict())
        }

        # Add overall CPU usage
        cpu_info['overall_percent'] = sum(cpu_info['cpu_percent']) / len(cpu_info['cpu_percent'])

        return cpu_info
    except Exception as e:
        logger.error(f"Error getting CPU info: {str(e)}")
        return {
            'error': f"Failed to retrieve CPU information: {str(e)}",
            'physical_cores': 0,
            'total_cores': 0,
            'cpu_percent': [0],
            'overall_percent': 0,
            'cpu_freq': {
                'current': None,
                'min': None,
                'max': None
            },
            'cpu_stats': {},
            'cpu_times_percent': {}
        }

def get_memory_info():
    """Get memory usage information."""
    try:
        # Virtual memory
        virtual_memory = psutil.virtual_memory()
        swap_memory = psutil.swap_memory()

        memory_info = {
            'virtual': {
                'total': virtual_memory.total,
                'available': virtual_memory.available,
                'used': virtual_memory.used,
                'percent': virtual_memory.percent,
                'total_gb': round(virtual_memory.total / (1024**3), 2),
                'available_gb': round(virtual_memory.available / (1024**3), 2),
                'used_gb': round(virtual_memory.used / (1024**3), 2)
            },
            'swap': {
                'total': swap_memory.total,
                'used': swap_memory.used,
                'free': swap_memory.free,
                'percent': swap_memory.percent,
                'total_gb': round(swap_memory.total / (1024**3), 2),
                'used_gb': round(swap_memory.used / (1024**3), 2),
                'free_gb': round(swap_memory.free / (1024**3), 2)
            }
        }

        return memory_info
    except Exception as e:
        logger.error(f"Error getting memory info: {str(e)}")
        return {
            'error': f"Failed to retrieve memory information: {str(e)}"
        }

def get_disk_info():
    """Get disk usage information."""
    try:
        disk_info = {
            'partitions': [],
            'io_counters': {}
        }

        # Get disk partitions
        for partition in psutil.disk_partitions():
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
                disk_info['partitions'].append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'opts': partition.opts,
                    'total': partition_usage.total,
                    'used': partition_usage.used,
                    'free': partition_usage.free,
                    'percent': partition_usage.percent,
                    'total_gb': round(partition_usage.total / (1024**3), 2),
                    'used_gb': round(partition_usage.used / (1024**3), 2),
                    'free_gb': round(partition_usage.free / (1024**3), 2)
                })
            except (PermissionError, FileNotFoundError) as e:
                # Skip partitions that can't be accessed
                logger.warning(f"Could not access partition {partition.mountpoint}: {str(e)}")
                continue

        # Get disk I/O counters
        try:
            io_counters = psutil.disk_io_counters(perdisk=True)
            for disk, counters in io_counters.items():
                disk_info['io_counters'][disk] = dict(counters._asdict())
        except Exception as e:
            logger.warning(f"Could not get disk I/O counters: {str(e)}")

        return disk_info
    except Exception as e:
        logger.error(f"Error getting disk info: {str(e)}")
        return {
            'error': f"Failed to retrieve disk information: {str(e)}"
        }

def get_network_info():
    """Get network information and statistics."""
    try:
        network_info = {
            'interfaces': {},
            'connections': []
        }

        # Get network interfaces
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()

        for interface, addrs in net_if_addrs.items():
            addresses = []
            for addr in addrs:
                addresses.append({
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                })

            # Add interface stats if available
            if interface in net_if_stats:
                stats = net_if_stats[interface]
                network_info['interfaces'][interface] = {
                    'addresses': addresses,
                    'stats': {
                        'isup': stats.isup,
                        'duplex': str(stats.duplex),
                        'speed': stats.speed,
                        'mtu': stats.mtu
                    }
                }
            else:
                network_info['interfaces'][interface] = {
                    'addresses': addresses
                }

        # Get network I/O counters
        net_io_counters = psutil.net_io_counters(pernic=True)
        for interface, counters in net_io_counters.items():
            if interface in network_info['interfaces']:
                network_info['interfaces'][interface]['io_counters'] = dict(counters._asdict())

        # Get network connections (limited due to permissions)
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                network_info['connections'].append({
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
        except (psutil.AccessDenied, PermissionError) as e:
            logger.warning(f"Could not get network connections due to permissions: {str(e)}")
            network_info['connections_error'] = "Permission denied to access network connections"

        return network_info
    except Exception as e:
        logger.error(f"Error getting network info: {str(e)}")
        return {
            'error': f"Failed to retrieve network information: {str(e)}"
        }

def get_system_uptime():
    """Get system uptime information."""
    try:
        # Get boot time
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.datetime.now() - boot_time

        # Format uptime
        days, remainder = divmod(uptime.total_seconds(), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)

        uptime_info = {
            'boot_time': boot_time.strftime('%Y-%m-%d %H:%M:%S'),
            'uptime_seconds': uptime.total_seconds(),
            'uptime_formatted': f"{int(days)} days, {int(hours)} hours, {int(minutes)} minutes",
            'days': int(days),
            'hours': int(hours),
            'minutes': int(minutes),
            'seconds': int(seconds)
        }

        return uptime_info
    except Exception as e:
        logger.error(f"Error getting system uptime: {str(e)}")
        return {
            'error': f"Failed to retrieve system uptime: {str(e)}"
        }

def get_system_load():
    """Get system load averages (1, 5, 15 minutes)."""
    try:
        load_avg = psutil.getloadavg()
        load_info = {
            'load_1_min': load_avg[0],
            'load_5_min': load_avg[1],
            'load_15_min': load_avg[2],
            'cpu_count': psutil.cpu_count(logical=True),
            'normalized_load_1': load_avg[0] / psutil.cpu_count(logical=True),
            'normalized_load_5': load_avg[1] / psutil.cpu_count(logical=True),
            'normalized_load_15': load_avg[2] / psutil.cpu_count(logical=True)
        }
        return load_info
    except Exception as e:
        logger.error(f"Error getting system load: {str(e)}")
        return {
            'error': f"Failed to retrieve system load: {str(e)}"
        }

def get_all_system_metrics():
    """Get all system metrics in a single call."""
    return {
        'system_info': get_system_info(),
        'cpu_info': get_cpu_info(),
        'memory_info': get_memory_info(),
        'disk_info': get_disk_info(),
        'network_info': get_network_info(),
        'uptime_info': get_system_uptime(),
        'load_info': get_system_load(),
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
