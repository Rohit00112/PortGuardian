import sqlite3
import psutil
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import json

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='enhanced_process_manager.log',
    filemode='a'
)
logger = logging.getLogger('enhanced_process_manager')

class EnhancedProcessManager:
    """Enhanced process manager with historical tracking and detailed analytics."""
    
    def __init__(self, db_path='process_history.db'):
        self.db_path = db_path
        self.monitoring = False
        self.monitor_thread = None
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize the process history database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create process_snapshots table for historical data
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS process_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        pid INTEGER NOT NULL,
                        name TEXT,
                        status TEXT,
                        username TEXT,
                        cpu_percent REAL,
                        memory_percent REAL,
                        memory_rss INTEGER,
                        memory_vms INTEGER,
                        num_threads INTEGER,
                        num_fds INTEGER,
                        create_time DATETIME,
                        command TEXT,
                        cwd TEXT,
                        parent_pid INTEGER,
                        nice INTEGER,
                        ionice_class INTEGER,
                        ionice_value INTEGER,
                        cpu_times_user REAL,
                        cpu_times_system REAL,
                        io_read_count INTEGER,
                        io_write_count INTEGER,
                        io_read_bytes INTEGER,
                        io_write_bytes INTEGER
                    )
                ''')
                
                # Create process_events table for lifecycle events
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS process_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        pid INTEGER NOT NULL,
                        name TEXT,
                        event_type TEXT NOT NULL,
                        details TEXT,
                        user_id TEXT
                    )
                ''')
                
                # Create process_connections table for network tracking
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS process_connections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        pid INTEGER NOT NULL,
                        local_ip TEXT,
                        local_port INTEGER,
                        remote_ip TEXT,
                        remote_port INTEGER,
                        status TEXT,
                        family TEXT,
                        type TEXT
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_pid ON process_snapshots(pid)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON process_snapshots(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_pid ON process_events(pid)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON process_events(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_pid ON process_connections(pid)')
                
                conn.commit()
                logger.info("Enhanced process manager database initialized successfully")
                
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            raise
    
    def get_enhanced_process_info(self, pid: int) -> Optional[Dict]:
        """Get comprehensive process information with historical data."""
        try:
            process = psutil.Process(pid)
            
            # Get current process information
            current_info = self._get_detailed_process_info(process)
            
            # Get historical data
            historical_data = self._get_process_history(pid)
            
            # Get process events
            events = self._get_process_events(pid)
            
            # Get connection history
            connections = self._get_process_connections(pid)
            
            # Calculate performance metrics
            performance_metrics = self._calculate_performance_metrics(pid)
            
            # Combine all information
            enhanced_info = {
                **current_info,
                'historical_data': historical_data,
                'events': events,
                'connections': connections,
                'performance_metrics': performance_metrics,
                'uptime': self._calculate_uptime(current_info.get('create_time')),
                'resource_trends': self._get_resource_trends(pid)
            }
            
            return enhanced_info
            
        except psutil.NoSuchProcess:
            logger.error(f"Process with PID {pid} not found")
            return None
        except Exception as e:
            logger.error(f"Error getting enhanced process info for PID {pid}: {str(e)}")
            return None
    
    def _get_detailed_process_info(self, process: psutil.Process) -> Dict:
        """Get detailed current process information."""
        try:
            # Basic info
            info = {
                'pid': process.pid,
                'name': process.name(),
                'status': process.status(),
                'username': process.username(),
                'create_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                'command': ' '.join(process.cmdline()),
                'cwd': process.cwd(),
            }
            
            # CPU and memory info
            try:
                info.update({
                    'cpu_percent': process.cpu_percent(interval=0.1),
                    'memory_percent': process.memory_percent(),
                    'memory_info': dict(process.memory_info()._asdict()),
                    'memory_full_info': dict(process.memory_full_info()._asdict()) if hasattr(process, 'memory_full_info') else {},
                    'cpu_times': dict(process.cpu_times()._asdict()),
                    'cpu_affinity': process.cpu_affinity() if hasattr(process, 'cpu_affinity') else [],
                })
            except (psutil.AccessDenied, AttributeError):
                info.update({
                    'cpu_percent': 0,
                    'memory_percent': 0,
                    'memory_info': {},
                    'memory_full_info': {},
                    'cpu_times': {},
                    'cpu_affinity': [],
                })
            
            # Process details
            try:
                info.update({
                    'num_threads': process.num_threads(),
                    'num_fds': process.num_fds() if hasattr(process, 'num_fds') else 0,
                    'nice': process.nice(),
                    'ionice': dict(process.ionice()._asdict()) if hasattr(process, 'ionice') else {},
                    'terminal': process.terminal() if hasattr(process, 'terminal') else None,
                    'environ': dict(process.environ()) if hasattr(process, 'environ') else {},
                })
            except (psutil.AccessDenied, AttributeError):
                info.update({
                    'num_threads': 0,
                    'num_fds': 0,
                    'nice': 0,
                    'ionice': {},
                    'terminal': None,
                    'environ': {},
                })
            
            # I/O information
            try:
                io_counters = process.io_counters()
                info['io_counters'] = dict(io_counters._asdict())
            except (psutil.AccessDenied, AttributeError):
                info['io_counters'] = {}
            
            # Parent and children
            try:
                parent = process.parent()
                info['parent'] = {
                    'pid': parent.pid,
                    'name': parent.name()
                } if parent else None
                
                children = process.children()
                info['children'] = [
                    {'pid': child.pid, 'name': child.name()}
                    for child in children
                ]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info['parent'] = None
                info['children'] = []
            
            # Network connections
            try:
                connections = process.connections()
                info['connections'] = []
                for conn in connections:
                    conn_info = {
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status
                    }
                    info['connections'].append(conn_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info['connections'] = []
            
            # Open files
            try:
                open_files = process.open_files()
                info['open_files'] = [
                    {'path': f.path, 'fd': f.fd, 'position': getattr(f, 'position', None)}
                    for f in open_files[:20]  # Limit to first 20 files
                ]
                info['open_files_count'] = len(open_files)
            except (psutil.AccessDenied, AttributeError):
                info['open_files'] = []
                info['open_files_count'] = 0
            
            return info
            
        except Exception as e:
            logger.error(f"Error getting detailed process info: {str(e)}")
            return {'error': str(e)}
    
    def _get_process_history(self, pid: int, hours: int = 24) -> List[Dict]:
        """Get historical snapshots for a process."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM process_snapshots 
                    WHERE pid = ? AND timestamp > datetime('now', '-{} hours')
                    ORDER BY timestamp DESC
                    LIMIT 100
                '''.format(hours), (pid,))
                
                columns = [description[0] for description in cursor.description]
                history = []
                
                for row in cursor.fetchall():
                    snapshot = dict(zip(columns, row))
                    history.append(snapshot)
                
                return history
                
        except Exception as e:
            logger.error(f"Error getting process history: {str(e)}")
            return []
    
    def _get_process_events(self, pid: int, limit: int = 50) -> List[Dict]:
        """Get process lifecycle events."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM process_events 
                    WHERE pid = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (pid, limit))
                
                columns = [description[0] for description in cursor.description]
                events = []
                
                for row in cursor.fetchall():
                    event = dict(zip(columns, row))
                    if event.get('details'):
                        try:
                            event['details'] = json.loads(event['details'])
                        except json.JSONDecodeError:
                            pass
                    events.append(event)
                
                return events
                
        except Exception as e:
            logger.error(f"Error getting process events: {str(e)}")
            return []

    def _get_process_connections(self, pid: int, hours: int = 24) -> List[Dict]:
        """Get process connection history."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM process_connections
                    WHERE pid = ? AND timestamp > datetime('now', '-{} hours')
                    ORDER BY timestamp DESC
                    LIMIT 100
                '''.format(hours), (pid,))

                columns = [description[0] for description in cursor.description]
                connections = []

                for row in cursor.fetchall():
                    connection = dict(zip(columns, row))
                    connections.append(connection)

                return connections

        except Exception as e:
            logger.error(f"Error getting process connections: {str(e)}")
            return []

    def _calculate_performance_metrics(self, pid: int) -> Dict:
        """Calculate performance metrics from historical data."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get recent snapshots for calculations
                cursor.execute('''
                    SELECT cpu_percent, memory_percent, memory_rss, timestamp
                    FROM process_snapshots
                    WHERE pid = ? AND timestamp > datetime('now', '-1 hour')
                    ORDER BY timestamp DESC
                    LIMIT 60
                ''', (pid,))

                snapshots = cursor.fetchall()

                if not snapshots:
                    return {}

                cpu_values = [s[0] for s in snapshots if s[0] is not None]
                memory_values = [s[1] for s in snapshots if s[1] is not None]
                rss_values = [s[2] for s in snapshots if s[2] is not None]

                metrics = {}

                if cpu_values:
                    metrics['cpu_avg'] = sum(cpu_values) / len(cpu_values)
                    metrics['cpu_max'] = max(cpu_values)
                    metrics['cpu_min'] = min(cpu_values)

                if memory_values:
                    metrics['memory_avg'] = sum(memory_values) / len(memory_values)
                    metrics['memory_max'] = max(memory_values)
                    metrics['memory_min'] = min(memory_values)

                if rss_values:
                    metrics['rss_avg'] = sum(rss_values) / len(rss_values)
                    metrics['rss_max'] = max(rss_values)
                    metrics['rss_min'] = min(rss_values)

                # Calculate trends
                if len(cpu_values) > 1:
                    metrics['cpu_trend'] = 'increasing' if cpu_values[0] > cpu_values[-1] else 'decreasing'

                if len(memory_values) > 1:
                    metrics['memory_trend'] = 'increasing' if memory_values[0] > memory_values[-1] else 'decreasing'

                return metrics

        except Exception as e:
            logger.error(f"Error calculating performance metrics: {str(e)}")
            return {}

    def _calculate_uptime(self, create_time_str: str) -> Dict:
        """Calculate process uptime information."""
        try:
            if not create_time_str or create_time_str == "unknown":
                return {}

            create_time = datetime.strptime(create_time_str, '%Y-%m-%d %H:%M:%S')
            uptime_delta = datetime.now() - create_time

            days = uptime_delta.days
            hours, remainder = divmod(uptime_delta.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            return {
                'total_seconds': uptime_delta.total_seconds(),
                'days': days,
                'hours': hours,
                'minutes': minutes,
                'seconds': seconds,
                'formatted': f"{days}d {hours}h {minutes}m {seconds}s"
            }

        except Exception as e:
            logger.error(f"Error calculating uptime: {str(e)}")
            return {}

    def _get_resource_trends(self, pid: int) -> Dict:
        """Get resource usage trends over time."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get hourly averages for the last 24 hours
                cursor.execute('''
                    SELECT
                        strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                        AVG(cpu_percent) as avg_cpu,
                        AVG(memory_percent) as avg_memory,
                        AVG(memory_rss) as avg_rss,
                        COUNT(*) as sample_count
                    FROM process_snapshots
                    WHERE pid = ? AND timestamp > datetime('now', '-24 hours')
                    GROUP BY strftime('%Y-%m-%d %H:00:00', timestamp)
                    ORDER BY hour
                ''', (pid,))

                trends = []
                for row in cursor.fetchall():
                    trends.append({
                        'hour': row[0],
                        'avg_cpu': round(row[1], 2) if row[1] else 0,
                        'avg_memory': round(row[2], 2) if row[2] else 0,
                        'avg_rss': int(row[3]) if row[3] else 0,
                        'sample_count': row[4]
                    })

                return {'hourly_trends': trends}

        except Exception as e:
            logger.error(f"Error getting resource trends: {str(e)}")
            return {}

    def start_monitoring(self):
        """Start background monitoring of processes."""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
            self.monitor_thread.start()
            logger.info("Enhanced process monitoring started")

    def stop_monitoring(self):
        """Stop background monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Enhanced process monitoring stopped")

    def _monitor_processes(self):
        """Background monitoring loop."""
        logger.info("Starting enhanced process monitoring loop")

        while self.monitoring:
            try:
                # Get all running processes
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        self._record_process_snapshot(proc.info['pid'])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Clean old data every hour
                if int(time.time()) % 3600 == 0:
                    self._cleanup_old_data()

                time.sleep(60)  # Record snapshots every minute

            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(60)

    def _record_process_snapshot(self, pid: int):
        """Record a snapshot of process state."""
        try:
            process = psutil.Process(pid)

            # Get process information
            snapshot_data = {
                'pid': pid,
                'name': process.name(),
                'status': process.status(),
                'username': process.username(),
                'create_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                'command': ' '.join(process.cmdline()),
                'cwd': process.cwd(),
            }

            # Add performance metrics
            try:
                snapshot_data.update({
                    'cpu_percent': process.cpu_percent(interval=0.1),
                    'memory_percent': process.memory_percent(),
                    'memory_rss': process.memory_info().rss,
                    'memory_vms': process.memory_info().vms,
                    'num_threads': process.num_threads(),
                    'num_fds': process.num_fds() if hasattr(process, 'num_fds') else 0,
                    'nice': process.nice(),
                })

                # Add I/O counters if available
                if hasattr(process, 'io_counters'):
                    io_counters = process.io_counters()
                    snapshot_data.update({
                        'io_read_count': io_counters.read_count,
                        'io_write_count': io_counters.write_count,
                        'io_read_bytes': io_counters.read_bytes,
                        'io_write_bytes': io_counters.write_bytes,
                    })

                # Add CPU times
                cpu_times = process.cpu_times()
                snapshot_data.update({
                    'cpu_times_user': cpu_times.user,
                    'cpu_times_system': cpu_times.system,
                })

                # Add ionice if available
                if hasattr(process, 'ionice'):
                    ionice = process.ionice()
                    snapshot_data.update({
                        'ionice_class': ionice.ioclass,
                        'ionice_value': ionice.value,
                    })

                # Add parent PID
                parent = process.parent()
                snapshot_data['parent_pid'] = parent.pid if parent else None

            except (psutil.AccessDenied, AttributeError):
                # Fill with defaults if access denied
                snapshot_data.update({
                    'cpu_percent': 0,
                    'memory_percent': 0,
                    'memory_rss': 0,
                    'memory_vms': 0,
                    'num_threads': 0,
                    'num_fds': 0,
                    'nice': 0,
                    'parent_pid': None,
                })

            # Store snapshot in database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Prepare column names and values
                columns = list(snapshot_data.keys())
                placeholders = ', '.join(['?' for _ in columns])
                column_names = ', '.join(columns)
                values = [snapshot_data[col] for col in columns]

                cursor.execute(f'''
                    INSERT INTO process_snapshots ({column_names})
                    VALUES ({placeholders})
                ''', values)

                conn.commit()

        except psutil.NoSuchProcess:
            # Process no longer exists
            pass
        except Exception as e:
            logger.error(f"Error recording process snapshot for PID {pid}: {str(e)}")

    def _cleanup_old_data(self):
        """Clean up old historical data."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Remove snapshots older than 7 days
                cursor.execute('''
                    DELETE FROM process_snapshots
                    WHERE timestamp < datetime('now', '-7 days')
                ''')

                # Remove events older than 30 days
                cursor.execute('''
                    DELETE FROM process_events
                    WHERE timestamp < datetime('now', '-30 days')
                ''')

                # Remove connections older than 24 hours
                cursor.execute('''
                    DELETE FROM process_connections
                    WHERE timestamp < datetime('now', '-1 day')
                ''')

                conn.commit()
                logger.info("Cleaned up old process data")

        except Exception as e:
            logger.error(f"Error cleaning up old data: {str(e)}")

    def log_process_event(self, pid: int, event_type: str, details: Dict = None, user_id: str = "system"):
        """Log a process lifecycle event."""
        try:
            process_name = "Unknown"
            try:
                process = psutil.Process(pid)
                process_name = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO process_events (pid, name, event_type, details, user_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    pid, process_name, event_type,
                    json.dumps(details) if details else None, user_id
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"Error logging process event: {str(e)}")

# Global enhanced process manager instance
enhanced_process_manager = EnhancedProcessManager()
