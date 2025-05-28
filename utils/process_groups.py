import sqlite3
import json
import psutil
import logging
import re
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from utils.process_manager import get_process_info, kill_process

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='process_groups.log',
    filemode='a'
)
logger = logging.getLogger('process_groups')

class ProcessGroupManager:
    """Manages process groups for batch operations."""

    def __init__(self, db_path='process_groups.db'):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize the process groups database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Create process_groups table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS process_groups (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        description TEXT,
                        color TEXT DEFAULT '#007bff',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        created_by TEXT,
                        is_active BOOLEAN DEFAULT 1
                    )
                ''')

                # Create group_rules table for pattern-based matching
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS group_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        group_id INTEGER,
                        rule_type TEXT NOT NULL, -- 'name_pattern', 'command_pattern', 'user', 'manual'
                        rule_value TEXT NOT NULL,
                        is_active BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (group_id) REFERENCES process_groups (id) ON DELETE CASCADE
                    )
                ''')

                # Create manual_group_processes for manually added processes
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS manual_group_processes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        group_id INTEGER,
                        pid INTEGER,
                        process_name TEXT,
                        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        added_by TEXT,
                        FOREIGN KEY (group_id) REFERENCES process_groups (id) ON DELETE CASCADE
                    )
                ''')

                conn.commit()
                logger.info("Process groups database initialized successfully")

        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            raise

    def create_group(self, name: str, description: str = "", color: str = "#007bff", created_by: str = "system") -> int:
        """Create a new process group."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO process_groups (name, description, color, created_by)
                    VALUES (?, ?, ?, ?)
                ''', (name, description, color, created_by))

                group_id = cursor.lastrowid
                conn.commit()

                logger.info(f"Created process group '{name}' with ID {group_id}")
                return group_id

        except sqlite3.IntegrityError:
            logger.error(f"Process group '{name}' already exists")
            raise ValueError(f"Process group '{name}' already exists")
        except Exception as e:
            logger.error(f"Error creating process group: {str(e)}")
            raise

    def add_rule(self, group_id: int, rule_type: str, rule_value: str) -> int:
        """Add a rule to a process group."""
        valid_rule_types = ['name_pattern', 'command_pattern', 'user', 'manual']
        if rule_type not in valid_rule_types:
            raise ValueError(f"Invalid rule type. Must be one of: {valid_rule_types}")

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO group_rules (group_id, rule_type, rule_value)
                    VALUES (?, ?, ?)
                ''', (group_id, rule_type, rule_value))

                rule_id = cursor.lastrowid
                conn.commit()

                logger.info(f"Added rule '{rule_type}:{rule_value}' to group {group_id}")
                return rule_id

        except Exception as e:
            logger.error(f"Error adding rule to group: {str(e)}")
            raise

    def add_manual_process(self, group_id: int, pid: int, added_by: str = "system") -> bool:
        """Manually add a specific process to a group."""
        try:
            # Get process info to validate and store process name
            process_info = get_process_info(pid)
            if not process_info:
                raise ValueError(f"Process with PID {pid} not found")

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO manual_group_processes
                    (group_id, pid, process_name, added_by)
                    VALUES (?, ?, ?, ?)
                ''', (group_id, pid, process_info['name'], added_by))

                conn.commit()

                logger.info(f"Manually added process {pid} ({process_info['name']}) to group {group_id}")
                return True

        except Exception as e:
            logger.error(f"Error adding manual process to group: {str(e)}")
            raise

    def get_groups(self) -> List[Dict]:
        """Get all process groups."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, name, description, color, created_at, created_by, is_active
                    FROM process_groups
                    WHERE is_active = 1
                    ORDER BY name
                ''')

                groups = []
                for row in cursor.fetchall():
                    group = {
                        'id': row[0],
                        'name': row[1],
                        'description': row[2],
                        'color': row[3],
                        'created_at': row[4],
                        'created_by': row[5],
                        'is_active': bool(row[6])
                    }

                    # Get rules for this group
                    group['rules'] = self.get_group_rules(group['id'])

                    # Get current processes in this group
                    group['processes'] = self.get_group_processes(group['id'])
                    group['process_count'] = len(group['processes'])

                    groups.append(group)

                return groups

        except Exception as e:
            logger.error(f"Error getting groups: {str(e)}")
            return []

    def get_group_rules(self, group_id: int) -> List[Dict]:
        """Get rules for a specific group."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, rule_type, rule_value, is_active, created_at
                    FROM group_rules
                    WHERE group_id = ? AND is_active = 1
                ''', (group_id,))

                rules = []
                for row in cursor.fetchall():
                    rules.append({
                        'id': row[0],
                        'rule_type': row[1],
                        'rule_value': row[2],
                        'is_active': bool(row[3]),
                        'created_at': row[4]
                    })

                return rules

        except Exception as e:
            logger.error(f"Error getting group rules: {str(e)}")
            return []

    def get_group_processes(self, group_id: int) -> List[Dict]:
        """Get all processes that belong to a specific group."""
        try:
            processes = []

            # Get group rules
            rules = self.get_group_rules(group_id)

            # Get all running processes
            running_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    running_processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Apply rules to find matching processes
            for process in running_processes:
                if self._process_matches_rules(process, rules):
                    process_info = get_process_info(process['pid'])
                    if process_info:
                        process_info['matched_by'] = 'rule'
                        processes.append(process_info)

            # Add manually added processes
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT pid, process_name, added_at, added_by
                    FROM manual_group_processes
                    WHERE group_id = ?
                ''', (group_id,))

                for row in cursor.fetchall():
                    pid, process_name, added_at, added_by = row
                    process_info = get_process_info(pid)
                    if process_info:  # Process is still running
                        process_info['matched_by'] = 'manual'
                        process_info['added_at'] = added_at
                        process_info['added_by'] = added_by
                        # Avoid duplicates
                        if not any(p['pid'] == pid for p in processes):
                            processes.append(process_info)

            return processes

        except Exception as e:
            logger.error(f"Error getting group processes: {str(e)}")
            return []

    def _process_matches_rules(self, process: Dict, rules: List[Dict]) -> bool:
        """Check if a process matches any of the group rules."""
        for rule in rules:
            rule_type = rule['rule_type']
            rule_value = rule['rule_value']

            try:
                if rule_type == 'name_pattern':
                    if re.search(rule_value, process.get('name', ''), re.IGNORECASE):
                        return True

                elif rule_type == 'command_pattern':
                    cmdline = ' '.join(process.get('cmdline', []))
                    if re.search(rule_value, cmdline, re.IGNORECASE):
                        return True

                elif rule_type == 'user':
                    if process.get('username') == rule_value:
                        return True

            except re.error:
                logger.warning(f"Invalid regex pattern in rule: {rule_value}")
                continue

        return False

    def kill_group_processes(self, group_id: int, user_id: str = "system") -> Dict:
        """Kill all processes in a group."""
        try:
            processes = self.get_group_processes(group_id)
            results = {
                'total': len(processes),
                'successful': 0,
                'failed': 0,
                'errors': []
            }

            for process in processes:
                try:
                    result = kill_process(process['pid'], user_id)
                    if result['success']:
                        results['successful'] += 1
                    else:
                        results['failed'] += 1
                        results['errors'].append({
                            'pid': process['pid'],
                            'name': process['name'],
                            'error': result['message']
                        })
                except Exception as e:
                    results['failed'] += 1
                    results['errors'].append({
                        'pid': process['pid'],
                        'name': process['name'],
                        'error': str(e)
                    })

            logger.info(f"Group {group_id} kill operation: {results['successful']} successful, {results['failed']} failed")
            return results

        except Exception as e:
            logger.error(f"Error killing group processes: {str(e)}")
            return {
                'total': 0,
                'successful': 0,
                'failed': 0,
                'errors': [{'error': str(e)}]
            }

    def delete_group(self, group_id: int) -> bool:
        """Delete a process group."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE process_groups SET is_active = 0 WHERE id = ?', (group_id,))
                conn.commit()

                logger.info(f"Deleted process group {group_id}")
                return True

        except Exception as e:
            logger.error(f"Error deleting group: {str(e)}")
            return False

    def remove_manual_process(self, group_id: int, pid: int) -> bool:
        """Remove a manually added process from a group."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM manual_group_processes
                    WHERE group_id = ? AND pid = ?
                ''', (group_id, pid))
                conn.commit()

                logger.info(f"Removed manual process {pid} from group {group_id}")
                return True

        except Exception as e:
            logger.error(f"Error removing manual process: {str(e)}")
            return False

    def get_predefined_groups(self) -> List[Dict]:
        """Get predefined system groups based on common process patterns."""
        predefined = [
            {
                'name': 'Web Servers',
                'description': 'Common web server processes',
                'color': '#28a745',
                'patterns': [
                    {'type': 'name_pattern', 'value': r'(nginx|apache|httpd)'},
                    {'type': 'command_pattern', 'value': r'(gunicorn|uwsgi|flask|django)'}
                ]
            },
            {
                'name': 'Database Servers',
                'description': 'Database server processes',
                'color': '#dc3545',
                'patterns': [
                    {'type': 'name_pattern', 'value': r'(mysql|postgres|mongodb|redis)'},
                    {'type': 'command_pattern', 'value': r'(mysqld|postgres|mongod|redis-server)'}
                ]
            },
            {
                'name': 'Development Tools',
                'description': 'Development and build tools',
                'color': '#ffc107',
                'patterns': [
                    {'type': 'name_pattern', 'value': r'(node|npm|yarn|python|java)'},
                    {'type': 'command_pattern', 'value': r'(webpack|babel|tsc|gradle|maven)'}
                ]
            },
            {
                'name': 'System Services',
                'description': 'Core system services',
                'color': '#6f42c1',
                'patterns': [
                    {'type': 'name_pattern', 'value': r'(systemd|launchd|cron|ssh)'},
                    {'type': 'command_pattern', 'value': r'(systemctl|service|daemon)'}
                ]
            }
        ]

        return predefined

    def create_predefined_group(self, predefined_group: Dict, created_by: str = "system") -> int:
        """Create a group from predefined template."""
        try:
            group_id = self.create_group(
                name=predefined_group['name'],
                description=predefined_group['description'],
                color=predefined_group['color'],
                created_by=created_by
            )

            # Add patterns as rules
            for pattern in predefined_group['patterns']:
                self.add_rule(group_id, pattern['type'], pattern['value'])

            return group_id

        except Exception as e:
            logger.error(f"Error creating predefined group: {str(e)}")
            raise

# Global instance
process_group_manager = ProcessGroupManager()
