import sqlite3
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

# Thread-safe database operations
db_lock = threading.Lock()

class MetricsStorage:
    """Storage system for historical system metrics."""
    
    def __init__(self, db_path: str = "metrics.db"):
        self.db_path = db_path
        self.logger = logging.getLogger('metrics_storage')
        self._init_database()
    
    def _init_database(self):
        """Initialize the SQLite database for metrics storage."""
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    metric_type TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT,
                    metadata TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for better query performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON system_metrics(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metric_type ON system_metrics(metric_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metric_name ON system_metrics(metric_name)')
            
            conn.commit()
            conn.close()
    
    def store_cpu_metrics(self, cpu_info: Dict[str, Any]):
        """Store CPU metrics."""
        timestamp = datetime.now().isoformat()
        
        metrics = [
            ('cpu', 'overall_percent', cpu_info.get('overall_percent', 0), '%', None),
            ('cpu', 'physical_cores', cpu_info.get('physical_cores', 0), 'count', None),
            ('cpu', 'total_cores', cpu_info.get('total_cores', 0), 'count', None),
        ]
        
        # Store per-core CPU usage
        if 'cpu_percent' in cpu_info:
            for i, cpu_percent in enumerate(cpu_info['cpu_percent']):
                metrics.append(('cpu', f'core_{i}_percent', cpu_percent, '%', None))
        
        # Store CPU frequency if available
        if cpu_info.get('cpu_freq', {}).get('current'):
            metrics.append(('cpu', 'frequency_current', cpu_info['cpu_freq']['current'], 'MHz', None))
        
        self._store_metrics(timestamp, metrics)
    
    def store_memory_metrics(self, memory_info: Dict[str, Any]):
        """Store memory metrics."""
        timestamp = datetime.now().isoformat()
        
        metrics = []
        
        # Virtual memory
        if 'virtual' in memory_info:
            virtual = memory_info['virtual']
            metrics.extend([
                ('memory', 'virtual_total', virtual.get('total', 0), 'bytes', None),
                ('memory', 'virtual_used', virtual.get('used', 0), 'bytes', None),
                ('memory', 'virtual_available', virtual.get('available', 0), 'bytes', None),
                ('memory', 'virtual_percent', virtual.get('percent', 0), '%', None),
            ])
        
        # Swap memory
        if 'swap' in memory_info:
            swap = memory_info['swap']
            metrics.extend([
                ('memory', 'swap_total', swap.get('total', 0), 'bytes', None),
                ('memory', 'swap_used', swap.get('used', 0), 'bytes', None),
                ('memory', 'swap_free', swap.get('free', 0), 'bytes', None),
                ('memory', 'swap_percent', swap.get('percent', 0), '%', None),
            ])
        
        self._store_metrics(timestamp, metrics)
    
    def store_disk_metrics(self, disk_info: Dict[str, Any]):
        """Store disk metrics."""
        timestamp = datetime.now().isoformat()
        
        metrics = []
        
        # Store partition usage
        if 'partitions' in disk_info:
            for partition in disk_info['partitions']:
                mountpoint = partition.get('mountpoint', 'unknown')
                safe_mountpoint = mountpoint.replace('/', '_').replace('\\', '_')
                
                metrics.extend([
                    ('disk', f'{safe_mountpoint}_total', partition.get('total', 0), 'bytes', 
                     json.dumps({'mountpoint': mountpoint, 'device': partition.get('device')})),
                    ('disk', f'{safe_mountpoint}_used', partition.get('used', 0), 'bytes',
                     json.dumps({'mountpoint': mountpoint, 'device': partition.get('device')})),
                    ('disk', f'{safe_mountpoint}_free', partition.get('free', 0), 'bytes',
                     json.dumps({'mountpoint': mountpoint, 'device': partition.get('device')})),
                    ('disk', f'{safe_mountpoint}_percent', partition.get('percent', 0), '%',
                     json.dumps({'mountpoint': mountpoint, 'device': partition.get('device')})),
                ])
        
        self._store_metrics(timestamp, metrics)
    
    def store_network_metrics(self, network_info: Dict[str, Any]):
        """Store network metrics."""
        timestamp = datetime.now().isoformat()
        
        metrics = []
        
        # Store interface statistics
        if 'interfaces' in network_info:
            for interface_name, interface in network_info['interfaces'].items():
                if 'io_counters' in interface:
                    io_counters = interface['io_counters']
                    metrics.extend([
                        ('network', f'{interface_name}_bytes_sent', io_counters.get('bytes_sent', 0), 'bytes',
                         json.dumps({'interface': interface_name})),
                        ('network', f'{interface_name}_bytes_recv', io_counters.get('bytes_recv', 0), 'bytes',
                         json.dumps({'interface': interface_name})),
                        ('network', f'{interface_name}_packets_sent', io_counters.get('packets_sent', 0), 'count',
                         json.dumps({'interface': interface_name})),
                        ('network', f'{interface_name}_packets_recv', io_counters.get('packets_recv', 0), 'count',
                         json.dumps({'interface': interface_name})),
                    ])
        
        self._store_metrics(timestamp, metrics)
    
    def store_load_metrics(self, load_info: Dict[str, Any]):
        """Store system load metrics."""
        timestamp = datetime.now().isoformat()
        
        metrics = [
            ('load', 'load_1_min', load_info.get('load_1_min', 0), 'load', None),
            ('load', 'load_5_min', load_info.get('load_5_min', 0), 'load', None),
            ('load', 'load_15_min', load_info.get('load_15_min', 0), 'load', None),
            ('load', 'normalized_load_1', load_info.get('normalized_load_1', 0), 'ratio', None),
            ('load', 'normalized_load_5', load_info.get('normalized_load_5', 0), 'ratio', None),
            ('load', 'normalized_load_15', load_info.get('normalized_load_15', 0), 'ratio', None),
        ]
        
        self._store_metrics(timestamp, metrics)
    
    def _store_metrics(self, timestamp: str, metrics: List[tuple]):
        """Store multiple metrics in the database."""
        try:
            with db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.executemany('''
                    INSERT INTO system_metrics 
                    (timestamp, metric_type, metric_name, value, unit, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', [(timestamp, *metric) for metric in metrics])
                
                conn.commit()
                conn.close()
        except Exception as e:
            self.logger.error(f"Failed to store metrics: {str(e)}")
    
    def get_metrics(self, 
                   metric_type: Optional[str] = None,
                   metric_name: Optional[str] = None,
                   start_time: Optional[str] = None,
                   end_time: Optional[str] = None,
                   limit: int = 1000) -> List[Dict[str, Any]]:
        """Retrieve metrics with filtering options."""
        
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build query with filters
            query = "SELECT * FROM system_metrics WHERE 1=1"
            params = []
            
            if metric_type:
                query += " AND metric_type = ?"
                params.append(metric_type)
            
            if metric_name:
                query += " AND metric_name = ?"
                params.append(metric_name)
            
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            columns = [description[0] for description in cursor.description]
            rows = cursor.fetchall()
            
            conn.close()
            
            # Convert to list of dictionaries
            metrics = []
            for row in rows:
                metric_dict = dict(zip(columns, row))
                # Parse JSON metadata if present
                if metric_dict.get('metadata'):
                    try:
                        metric_dict['metadata'] = json.loads(metric_dict['metadata'])
                    except json.JSONDecodeError:
                        pass
                metrics.append(metric_dict)
            
            return metrics
    
    def get_chart_data(self, 
                      metric_type: str,
                      metric_names: List[str],
                      hours: int = 24) -> Dict[str, List[Dict[str, Any]]]:
        """Get chart data for specific metrics over a time period."""
        
        start_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        chart_data = {}
        
        for metric_name in metric_names:
            metrics = self.get_metrics(
                metric_type=metric_type,
                metric_name=metric_name,
                start_time=start_time,
                limit=1000
            )
            
            # Reverse to get chronological order
            metrics.reverse()
            
            chart_data[metric_name] = [
                {
                    'timestamp': metric['timestamp'],
                    'value': metric['value'],
                    'unit': metric['unit']
                }
                for metric in metrics
            ]
        
        return chart_data
    
    def cleanup_old_metrics(self, days: int = 30):
        """Clean up metrics older than specified days."""
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        try:
            with db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute(
                    "DELETE FROM system_metrics WHERE timestamp < ?",
                    (cutoff_date,)
                )
                
                deleted_count = cursor.rowcount
                conn.commit()
                conn.close()
                
                self.logger.info(f"Cleaned up {deleted_count} old metrics")
                return deleted_count
        except Exception as e:
            self.logger.error(f"Failed to cleanup old metrics: {str(e)}")
            return 0

# Global metrics storage instance
metrics_storage = MetricsStorage()
