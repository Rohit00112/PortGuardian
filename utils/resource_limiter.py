import sqlite3
import psutil
import logging
import threading
import time
import os
import signal
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from enum import Enum
import json

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='resource_limiter.log',
    filemode='a'
)
logger = logging.getLogger('resource_limiter')

class LimitAction(Enum):
    """Actions to take when resource limits are exceeded."""
    WARN = "warn"
    THROTTLE = "throttle"
    SUSPEND = "suspend"
    KILL = "kill"

class LimitType(Enum):
    """Types of resource limits."""
    CPU_PERCENT = "cpu_percent"
    MEMORY_PERCENT = "memory_percent"
    MEMORY_RSS = "memory_rss"
    MEMORY_VMS = "memory_vms"

class ResourceLimiter:
    """Manages and enforces resource limits for processes."""
    
    def __init__(self, db_path='resource_limits.db'):
        self.db_path = db_path
        self.monitoring = False
        self.monitor_thread = None
        self.lock = threading.Lock()
        self.violation_counts = {}  # Track consecutive violations
        self.init_database()
    
    def init_database(self):
        """Initialize the resource limits database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create resource_limits table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS resource_limits (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pid INTEGER,
                        process_name TEXT,
                        limit_type TEXT NOT NULL,
                        limit_value REAL NOT NULL,
                        action TEXT NOT NULL,
                        enabled BOOLEAN DEFAULT 1,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        created_by TEXT,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_by TEXT,
                        description TEXT
                    )
                ''')
                
                # Create limit_violations table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS limit_violations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        pid INTEGER NOT NULL,
                        process_name TEXT,
                        limit_type TEXT NOT NULL,
                        limit_value REAL NOT NULL,
                        actual_value REAL NOT NULL,
                        action_taken TEXT,
                        success BOOLEAN,
                        details TEXT
                    )
                ''')
                
                # Create process_priorities table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS process_priorities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pid INTEGER,
                        process_name TEXT,
                        nice_value INTEGER NOT NULL,
                        set_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        set_by TEXT,
                        previous_nice INTEGER
                    )
                ''')
                
                # Create limit_templates table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS limit_templates (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        description TEXT,
                        limits TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        created_by TEXT,
                        is_system BOOLEAN DEFAULT 0
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_limits_pid ON resource_limits(pid)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_violations_pid ON limit_violations(pid)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_violations_timestamp ON limit_violations(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_priorities_pid ON process_priorities(pid)')
                
                conn.commit()
                
                # Create default templates
                self._create_default_templates()
                
                logger.info("Resource limiter database initialized successfully")
                
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            raise
    
    def _create_default_templates(self):
        """Create default resource limit templates."""
        default_templates = [
            {
                'name': 'Web Server',
                'description': 'Limits for web server processes (nginx, apache)',
                'limits': [
                    {'type': 'cpu_percent', 'value': 80, 'action': 'throttle'},
                    {'type': 'memory_percent', 'value': 70, 'action': 'warn'}
                ]
            },
            {
                'name': 'Database Server',
                'description': 'Limits for database processes (mysql, postgres)',
                'limits': [
                    {'type': 'cpu_percent', 'value': 90, 'action': 'warn'},
                    {'type': 'memory_percent', 'value': 80, 'action': 'warn'}
                ]
            },
            {
                'name': 'Development Tools',
                'description': 'Limits for development processes (node, python)',
                'limits': [
                    {'type': 'cpu_percent', 'value': 60, 'action': 'throttle'},
                    {'type': 'memory_percent', 'value': 50, 'action': 'warn'}
                ]
            },
            {
                'name': 'Background Services',
                'description': 'Limits for background/daemon processes',
                'limits': [
                    {'type': 'cpu_percent', 'value': 30, 'action': 'throttle'},
                    {'type': 'memory_percent', 'value': 40, 'action': 'warn'}
                ]
            }
        ]
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for template in default_templates:
                    cursor.execute('''
                        INSERT OR IGNORE INTO limit_templates (name, description, limits, created_by, is_system)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        template['name'],
                        template['description'],
                        json.dumps(template['limits']),
                        'system',
                        True
                    ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error creating default templates: {str(e)}")
    
    def set_resource_limit(self, pid: int, limit_type: str, limit_value: float, 
                          action: str, created_by: str = "system", description: str = "") -> int:
        """Set a resource limit for a process."""
        try:
            # Validate inputs
            if limit_type not in [lt.value for lt in LimitType]:
                raise ValueError(f"Invalid limit type: {limit_type}")
            
            if action not in [la.value for la in LimitAction]:
                raise ValueError(f"Invalid action: {action}")
            
            if limit_value <= 0:
                raise ValueError("Limit value must be positive")
            
            # Get process name
            process_name = "Unknown"
            try:
                process = psutil.Process(pid)
                process_name = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if limit already exists for this process and type
                cursor.execute('''
                    SELECT id FROM resource_limits 
                    WHERE pid = ? AND limit_type = ? AND enabled = 1
                ''', (pid, limit_type))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing limit
                    cursor.execute('''
                        UPDATE resource_limits 
                        SET limit_value = ?, action = ?, updated_at = CURRENT_TIMESTAMP, 
                            updated_by = ?, description = ?
                        WHERE id = ?
                    ''', (limit_value, action, created_by, description, existing[0]))
                    limit_id = existing[0]
                else:
                    # Create new limit
                    cursor.execute('''
                        INSERT INTO resource_limits 
                        (pid, process_name, limit_type, limit_value, action, created_by, description)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (pid, process_name, limit_type, limit_value, action, created_by, description))
                    limit_id = cursor.lastrowid
                
                conn.commit()
                
                logger.info(f"Set {limit_type} limit of {limit_value} for process {pid} ({process_name})")
                return limit_id
                
        except Exception as e:
            logger.error(f"Error setting resource limit: {str(e)}")
            raise
    
    def remove_resource_limit(self, limit_id: int) -> bool:
        """Remove a resource limit."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE resource_limits SET enabled = 0 WHERE id = ?', (limit_id,))
                conn.commit()
                
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Error removing resource limit: {str(e)}")
            return False
    
    def get_process_limits(self, pid: int) -> List[Dict]:
        """Get all active limits for a process."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM resource_limits 
                    WHERE pid = ? AND enabled = 1
                    ORDER BY created_at DESC
                ''', (pid,))
                
                columns = [description[0] for description in cursor.description]
                limits = []
                
                for row in cursor.fetchall():
                    limit = dict(zip(columns, row))
                    limits.append(limit)
                
                return limits
                
        except Exception as e:
            logger.error(f"Error getting process limits: {str(e)}")
            return []
    
    def get_all_limits(self) -> List[Dict]:
        """Get all active resource limits."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM resource_limits 
                    WHERE enabled = 1
                    ORDER BY created_at DESC
                ''')
                
                columns = [description[0] for description in cursor.description]
                limits = []
                
                for row in cursor.fetchall():
                    limit = dict(zip(columns, row))
                    limits.append(limit)
                
                return limits
                
        except Exception as e:
            logger.error(f"Error getting all limits: {str(e)}")
            return []

    def set_process_priority(self, pid: int, nice_value: int, set_by: str = "system") -> bool:
        """Set process priority (nice value)."""
        try:
            process = psutil.Process(pid)
            previous_nice = process.nice()

            # Set new nice value
            process.nice(nice_value)

            # Log the change
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO process_priorities
                    (pid, process_name, nice_value, set_by, previous_nice)
                    VALUES (?, ?, ?, ?, ?)
                ''', (pid, process.name(), nice_value, set_by, previous_nice))
                conn.commit()

            logger.info(f"Set nice value {nice_value} for process {pid} (was {previous_nice})")
            return True

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Error setting process priority: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error setting process priority: {str(e)}")
            return False

    def start_monitoring(self):
        """Start resource limit monitoring."""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_limits, daemon=True)
            self.monitor_thread.start()
            logger.info("Resource limit monitoring started")

    def stop_monitoring(self):
        """Stop resource limit monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Resource limit monitoring stopped")

    def _monitor_limits(self):
        """Main monitoring loop for resource limits."""
        logger.info("Starting resource limit monitoring loop")

        while self.monitoring:
            try:
                limits = self.get_all_limits()

                for limit in limits:
                    self._check_process_limit(limit)

                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(30)  # Wait longer on error

    def _check_process_limit(self, limit: Dict):
        """Check if a process is violating its resource limit."""
        try:
            pid = limit['pid']
            limit_type = limit['limit_type']
            limit_value = limit['limit_value']
            action = limit['action']

            # Check if process still exists
            try:
                process = psutil.Process(pid)
            except psutil.NoSuchProcess:
                # Process no longer exists, disable the limit
                self.remove_resource_limit(limit['id'])
                return

            # Get current resource usage
            current_value = self._get_current_resource_value(process, limit_type)

            if current_value is None:
                return

            # Check if limit is exceeded
            if current_value > limit_value:
                self._handle_limit_violation(limit, current_value)
            else:
                # Reset violation count if within limits
                if pid in self.violation_counts:
                    self.violation_counts[pid] = 0

        except Exception as e:
            logger.error(f"Error checking process limit: {str(e)}")

    def _get_current_resource_value(self, process: psutil.Process, limit_type: str) -> Optional[float]:
        """Get current resource usage value for a process."""
        try:
            if limit_type == LimitType.CPU_PERCENT.value:
                return process.cpu_percent(interval=1.0)
            elif limit_type == LimitType.MEMORY_PERCENT.value:
                return process.memory_percent()
            elif limit_type == LimitType.MEMORY_RSS.value:
                return process.memory_info().rss / (1024 * 1024)  # MB
            elif limit_type == LimitType.MEMORY_VMS.value:
                return process.memory_info().vms / (1024 * 1024)  # MB
            else:
                return None

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except Exception as e:
            logger.error(f"Error getting resource value: {str(e)}")
            return None

    def _handle_limit_violation(self, limit: Dict, current_value: float):
        """Handle a resource limit violation."""
        pid = limit['pid']
        limit_type = limit['limit_type']
        limit_value = limit['limit_value']
        action = limit['action']

        # Track consecutive violations
        if pid not in self.violation_counts:
            self.violation_counts[pid] = 0
        self.violation_counts[pid] += 1

        # Only take action after multiple consecutive violations to avoid false positives
        if self.violation_counts[pid] < 3:
            return

        success = False
        details = ""

        try:
            process = psutil.Process(pid)
            process_name = process.name()

            if action == LimitAction.WARN.value:
                success = True
                details = f"Warning: Process exceeding {limit_type} limit"
                logger.warning(f"Process {pid} ({process_name}) exceeding {limit_type} limit: {current_value} > {limit_value}")

            elif action == LimitAction.THROTTLE.value:
                # Increase nice value to lower priority
                current_nice = process.nice()
                new_nice = min(current_nice + 5, 19)  # Max nice value is 19
                process.nice(new_nice)
                success = True
                details = f"Throttled process by setting nice value from {current_nice} to {new_nice}"
                logger.info(f"Throttled process {pid} ({process_name}): nice {current_nice} -> {new_nice}")

            elif action == LimitAction.SUSPEND.value:
                process.suspend()
                success = True
                details = "Process suspended due to resource limit violation"
                logger.info(f"Suspended process {pid} ({process_name}) for exceeding {limit_type} limit")

            elif action == LimitAction.KILL.value:
                process.terminate()
                success = True
                details = "Process terminated due to resource limit violation"
                logger.warning(f"Terminated process {pid} ({process_name}) for exceeding {limit_type} limit")

            # Log the violation
            self._log_violation(limit, current_value, action, success, details)

            # Reset violation count after taking action
            self.violation_counts[pid] = 0

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            details = f"Failed to take action: {str(e)}"
            self._log_violation(limit, current_value, action, False, details)
        except Exception as e:
            details = f"Error taking action: {str(e)}"
            self._log_violation(limit, current_value, action, False, details)
            logger.error(f"Error handling limit violation: {str(e)}")

    def _log_violation(self, limit: Dict, current_value: float, action: str, success: bool, details: str):
        """Log a resource limit violation."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO limit_violations
                    (pid, process_name, limit_type, limit_value, actual_value, action_taken, success, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    limit['pid'], limit['process_name'], limit['limit_type'],
                    limit['limit_value'], current_value, action, success, details
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"Error logging violation: {str(e)}")

    def get_violations(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get recent resource limit violations."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM limit_violations
                    WHERE timestamp > datetime('now', '-{} hours')
                    ORDER BY timestamp DESC
                    LIMIT ?
                '''.format(hours), (limit,))

                columns = [description[0] for description in cursor.description]
                violations = []

                for row in cursor.fetchall():
                    violation = dict(zip(columns, row))
                    violations.append(violation)

                return violations

        except Exception as e:
            logger.error(f"Error getting violations: {str(e)}")
            return []

    def get_templates(self) -> List[Dict]:
        """Get all resource limit templates."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM limit_templates
                    ORDER BY is_system DESC, name ASC
                ''')

                columns = [description[0] for description in cursor.description]
                templates = []

                for row in cursor.fetchall():
                    template = dict(zip(columns, row))
                    try:
                        template['limits'] = json.loads(template['limits'])
                    except json.JSONDecodeError:
                        template['limits'] = []
                    templates.append(template)

                return templates

        except Exception as e:
            logger.error(f"Error getting templates: {str(e)}")
            return []

    def apply_template(self, pid: int, template_name: str, created_by: str = "system") -> bool:
        """Apply a resource limit template to a process."""
        try:
            templates = self.get_templates()
            template = next((t for t in templates if t['name'] == template_name), None)

            if not template:
                raise ValueError(f"Template '{template_name}' not found")

            for limit_config in template['limits']:
                self.set_resource_limit(
                    pid=pid,
                    limit_type=limit_config['type'],
                    limit_value=limit_config['value'],
                    action=limit_config['action'],
                    created_by=created_by,
                    description=f"Applied from template: {template_name}"
                )

            logger.info(f"Applied template '{template_name}' to process {pid}")
            return True

        except Exception as e:
            logger.error(f"Error applying template: {str(e)}")
            return False

# Global resource limiter instance
resource_limiter = ResourceLimiter()
