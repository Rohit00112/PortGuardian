import sqlite3
import psutil
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
from enum import Enum
import ipaddress

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='security_monitor.log',
    filemode='a'
)
logger = logging.getLogger('security_monitor')

class ThreatLevel(Enum):
    """Enumeration of threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(Enum):
    """Enumeration of threat types."""
    PORT_SCAN = "port_scan"
    RAPID_CONNECTIONS = "rapid_connections"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    FAILED_CONNECTIONS = "failed_connections"
    UNUSUAL_PORTS = "unusual_ports"

class SecurityMonitor:
    """Monitor network connections for suspicious activities and port scanning attempts."""

    def __init__(self, db_path='security_monitor.db'):
        self.db_path = db_path
        self.connection_history = defaultdict(lambda: deque(maxlen=1000))  # IP -> connection times
        self.port_access_history = defaultdict(lambda: defaultdict(int))  # IP -> {port: count}
        self.monitoring = False
        self.monitor_thread = None
        self.lock = threading.Lock()

        # Configuration thresholds
        self.config = {
            'scan_threshold': 10,  # connections to different ports within time window
            'time_window': 60,     # seconds
            'rapid_threshold': 20, # connections within rapid window
            'rapid_window': 10,    # seconds for rapid detection
            'suspicious_ports': [22, 23, 135, 139, 445, 1433, 3389],  # commonly targeted ports
            'whitelist_ips': ['127.0.0.1', '::1'],  # IPs to ignore
        }

        self.init_database()

    def init_database(self):
        """Initialize the security monitoring database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Create connection_logs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS connection_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        source_ip TEXT NOT NULL,
                        source_port INTEGER,
                        dest_ip TEXT NOT NULL,
                        dest_port INTEGER NOT NULL,
                        protocol TEXT,
                        status TEXT,
                        process_name TEXT,
                        process_pid INTEGER
                    )
                ''')

                # Create threat_detections table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_detections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        source_ip TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        threat_level TEXT NOT NULL,
                        description TEXT,
                        details TEXT,
                        port_count INTEGER,
                        connection_count INTEGER,
                        time_window INTEGER,
                        is_resolved BOOLEAN DEFAULT 0,
                        resolved_at DATETIME,
                        resolved_by TEXT
                    )
                ''')

                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_source_ip ON connection_logs(source_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_timestamp ON connection_logs(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_source_ip ON threat_detections(source_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threat_detections(timestamp)')

                conn.commit()
                logger.info("Security monitor database initialized successfully")

        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            raise

    def start_monitoring(self):
        """Start the security monitoring in a background thread."""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_connections, daemon=True)
            self.monitor_thread.start()
            logger.info("Security monitoring started")

    def stop_monitoring(self):
        """Stop the security monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Security monitoring stopped")

    def _monitor_connections(self):
        """Main monitoring loop that runs in background thread."""
        logger.info("Starting connection monitoring loop")

        while self.monitoring:
            try:
                current_connections = self._get_current_connections()

                for conn in current_connections:
                    self._log_connection(conn)
                    self._analyze_connection(conn)

                # Clean old data every 5 minutes
                if int(time.time()) % 300 == 0:
                    self._cleanup_old_data()

                time.sleep(5)  # Check every 5 seconds

            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(10)  # Wait longer on error

    def _get_current_connections(self) -> List[Dict]:
        """Get current network connections."""
        connections = []

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    continue  # Skip listening sockets

                if not conn.raddr:
                    continue  # Skip connections without remote address

                # Get process info if available
                process_name = "Unknown"
                process_pid = None

                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        process_name = process.name()
                        process_pid = conn.pid
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                connection_info = {
                    'source_ip': conn.raddr.ip,
                    'source_port': conn.raddr.port,
                    'dest_ip': conn.laddr.ip if conn.laddr else 'Unknown',
                    'dest_port': conn.laddr.port if conn.laddr else 0,
                    'protocol': 'TCP' if conn.type == 1 else 'UDP',
                    'status': conn.status,
                    'process_name': process_name,
                    'process_pid': process_pid
                }

                connections.append(connection_info)

        except Exception as e:
            logger.error(f"Error getting connections: {str(e)}")

        return connections

    def _log_connection(self, conn: Dict):
        """Log connection to database."""
        try:
            with sqlite3.connect(self.db_path) as db_conn:
                cursor = db_conn.cursor()
                cursor.execute('''
                    INSERT INTO connection_logs
                    (source_ip, source_port, dest_ip, dest_port, protocol, status, process_name, process_pid)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    conn['source_ip'], conn['source_port'], conn['dest_ip'],
                    conn['dest_port'], conn['protocol'], conn['status'],
                    conn['process_name'], conn['process_pid']
                ))
                db_conn.commit()

        except Exception as e:
            logger.error(f"Error logging connection: {str(e)}")

    def _analyze_connection(self, conn: Dict):
        """Analyze connection for suspicious patterns."""
        source_ip = conn['source_ip']
        dest_port = conn['dest_port']
        current_time = datetime.now()

        # Skip whitelisted IPs
        if source_ip in self.config['whitelist_ips']:
            return

        # Skip private/local IPs for external scanning detection
        try:
            ip_obj = ipaddress.ip_address(source_ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return
        except ValueError:
            pass  # Invalid IP, continue analysis

        with self.lock:
            # Track connection timing
            self.connection_history[source_ip].append(current_time)
            self.port_access_history[source_ip][dest_port] += 1

            # Analyze for port scanning
            self._detect_port_scanning(source_ip, current_time)

            # Analyze for rapid connections
            self._detect_rapid_connections(source_ip, current_time)

            # Analyze for suspicious ports
            self._detect_suspicious_port_access(source_ip, dest_port, current_time)

    def _detect_port_scanning(self, source_ip: str, current_time: datetime):
        """Detect potential port scanning activity."""
        time_threshold = current_time - timedelta(seconds=self.config['time_window'])

        # Count recent connections
        recent_connections = [t for t in self.connection_history[source_ip] if t > time_threshold]

        # Count unique ports accessed
        unique_ports = len(self.port_access_history[source_ip])

        if unique_ports >= self.config['scan_threshold'] and len(recent_connections) >= self.config['scan_threshold']:
            threat_level = ThreatLevel.HIGH if unique_ports > 20 else ThreatLevel.MEDIUM

            self._log_threat(
                source_ip=source_ip,
                threat_type=ThreatType.PORT_SCAN,
                threat_level=threat_level,
                description=f"Port scanning detected from {source_ip}",
                details=f"Accessed {unique_ports} different ports in {self.config['time_window']} seconds",
                port_count=unique_ports,
                connection_count=len(recent_connections),
                time_window=self.config['time_window']
            )

    def _detect_rapid_connections(self, source_ip: str, current_time: datetime):
        """Detect rapid connection attempts."""
        time_threshold = current_time - timedelta(seconds=self.config['rapid_window'])

        recent_connections = [t for t in self.connection_history[source_ip] if t > time_threshold]

        if len(recent_connections) >= self.config['rapid_threshold']:
            self._log_threat(
                source_ip=source_ip,
                threat_type=ThreatType.RAPID_CONNECTIONS,
                threat_level=ThreatLevel.MEDIUM,
                description=f"Rapid connection attempts from {source_ip}",
                details=f"{len(recent_connections)} connections in {self.config['rapid_window']} seconds",
                connection_count=len(recent_connections),
                time_window=self.config['rapid_window']
            )

    def _detect_suspicious_port_access(self, source_ip: str, dest_port: int, current_time: datetime):
        """Detect access to commonly targeted ports."""
        if dest_port in self.config['suspicious_ports']:
            self._log_threat(
                source_ip=source_ip,
                threat_type=ThreatType.UNUSUAL_PORTS,
                threat_level=ThreatLevel.LOW,
                description=f"Access to suspicious port {dest_port} from {source_ip}",
                details=f"Port {dest_port} is commonly targeted by attackers",
                port_count=1,
                connection_count=1
            )

    def _log_threat(self, source_ip: str, threat_type: ThreatType, threat_level: ThreatLevel,
                   description: str, details: str = "", port_count: int = 0,
                   connection_count: int = 0, time_window: int = 0):
        """Log a detected threat to the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Check if similar threat was already logged recently (avoid spam)
                cursor.execute('''
                    SELECT id FROM threat_detections
                    WHERE source_ip = ? AND threat_type = ?
                    AND timestamp > datetime('now', '-5 minutes')
                ''', (source_ip, threat_type.value))

                if cursor.fetchone():
                    return  # Similar threat already logged recently

                cursor.execute('''
                    INSERT INTO threat_detections
                    (source_ip, threat_type, threat_level, description, details,
                     port_count, connection_count, time_window)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    source_ip, threat_type.value, threat_level.value, description,
                    details, port_count, connection_count, time_window
                ))

                conn.commit()
                logger.warning(f"Threat detected: {description}")

        except Exception as e:
            logger.error(f"Error logging threat: {str(e)}")

    def _cleanup_old_data(self):
        """Clean up old connection logs and resolved threats."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Remove connection logs older than 24 hours
                cursor.execute('''
                    DELETE FROM connection_logs
                    WHERE timestamp < datetime('now', '-1 day')
                ''')

                # Remove resolved threats older than 7 days
                cursor.execute('''
                    DELETE FROM threat_detections
                    WHERE is_resolved = 1 AND resolved_at < datetime('now', '-7 days')
                ''')

                conn.commit()

                # Clean in-memory data
                cutoff_time = datetime.now() - timedelta(hours=1)
                with self.lock:
                    for ip in list(self.connection_history.keys()):
                        # Remove old connections from memory
                        self.connection_history[ip] = deque(
                            [t for t in self.connection_history[ip] if t > cutoff_time],
                            maxlen=1000
                        )

                        # Remove empty entries
                        if not self.connection_history[ip]:
                            del self.connection_history[ip]
                            if ip in self.port_access_history:
                                del self.port_access_history[ip]

        except Exception as e:
            logger.error(f"Error cleaning up old data: {str(e)}")

    def get_recent_threats(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get recent threat detections."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM threat_detections
                    WHERE timestamp > datetime('now', '-{} hours')
                    ORDER BY timestamp DESC
                    LIMIT ?
                '''.format(hours), (limit,))

                columns = [description[0] for description in cursor.description]
                threats = []

                for row in cursor.fetchall():
                    threat = dict(zip(columns, row))
                    threats.append(threat)

                return threats

        except Exception as e:
            logger.error(f"Error getting recent threats: {str(e)}")
            return []

    def get_threat_statistics(self) -> Dict:
        """Get threat detection statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Total threats
                cursor.execute("SELECT COUNT(*) FROM threat_detections")
                total_threats = cursor.fetchone()[0]

                # Threats by type
                cursor.execute('''
                    SELECT threat_type, COUNT(*) as count
                    FROM threat_detections
                    GROUP BY threat_type
                    ORDER BY count DESC
                ''')
                threat_types = dict(cursor.fetchall())

                # Threats by level
                cursor.execute('''
                    SELECT threat_level, COUNT(*) as count
                    FROM threat_detections
                    GROUP BY threat_level
                    ORDER BY count DESC
                ''')
                threat_levels = dict(cursor.fetchall())

                # Recent activity (last 24 hours)
                cursor.execute('''
                    SELECT COUNT(*) FROM threat_detections
                    WHERE timestamp > datetime('now', '-1 day')
                ''')
                recent_threats = cursor.fetchone()[0]

                # Top source IPs
                cursor.execute('''
                    SELECT source_ip, COUNT(*) as count
                    FROM threat_detections
                    GROUP BY source_ip
                    ORDER BY count DESC
                    LIMIT 10
                ''')
                top_sources = dict(cursor.fetchall())

                # Unresolved threats
                cursor.execute("SELECT COUNT(*) FROM threat_detections WHERE is_resolved = 0")
                unresolved_threats = cursor.fetchone()[0]

                return {
                    'total_threats': total_threats,
                    'threat_types': threat_types,
                    'threat_levels': threat_levels,
                    'recent_threats': recent_threats,
                    'top_sources': top_sources,
                    'unresolved_threats': unresolved_threats
                }

        except Exception as e:
            logger.error(f"Error getting threat statistics: {str(e)}")
            return {}

    def resolve_threat(self, threat_id: int, resolved_by: str = "system") -> bool:
        """Mark a threat as resolved."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE threat_detections
                    SET is_resolved = 1, resolved_at = datetime('now'), resolved_by = ?
                    WHERE id = ?
                ''', (resolved_by, threat_id))

                conn.commit()
                return cursor.rowcount > 0

        except Exception as e:
            logger.error(f"Error resolving threat: {str(e)}")
            return False

    def get_connection_logs(self, hours: int = 1, limit: int = 1000) -> List[Dict]:
        """Get recent connection logs."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM connection_logs
                    WHERE timestamp > datetime('now', '-{} hours')
                    ORDER BY timestamp DESC
                    LIMIT ?
                '''.format(hours), (limit,))

                columns = [description[0] for description in cursor.description]
                connections = []

                for row in cursor.fetchall():
                    connection = dict(zip(columns, row))
                    connections.append(connection)

                return connections

        except Exception as e:
            logger.error(f"Error getting connection logs: {str(e)}")
            return []

# Global security monitor instance
security_monitor = SecurityMonitor()
