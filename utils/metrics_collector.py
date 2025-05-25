import threading
import time
import logging
from datetime import datetime
from utils.system_monitor import get_all_system_metrics
from utils.metrics_storage import metrics_storage

class MetricsCollector:
    """Background metrics collector that periodically stores system metrics."""
    
    def __init__(self, collection_interval: int = 30):
        self.collection_interval = collection_interval  # seconds
        self.running = False
        self.thread = None
        self.logger = logging.getLogger('metrics_collector')
    
    def start(self):
        """Start the metrics collection thread."""
        if self.running:
            self.logger.warning("Metrics collector is already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._collect_loop, daemon=True)
        self.thread.start()
        self.logger.info(f"Started metrics collector with {self.collection_interval}s interval")
    
    def stop(self):
        """Stop the metrics collection thread."""
        if not self.running:
            self.logger.warning("Metrics collector is not running")
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        self.logger.info("Stopped metrics collector")
    
    def _collect_loop(self):
        """Main collection loop that runs in the background thread."""
        while self.running:
            try:
                self._collect_and_store_metrics()
            except Exception as e:
                self.logger.error(f"Error collecting metrics: {str(e)}")
            
            # Sleep for the specified interval
            time.sleep(self.collection_interval)
    
    def _collect_and_store_metrics(self):
        """Collect current system metrics and store them."""
        try:
            # Get all system metrics
            metrics = get_all_system_metrics()
            
            # Store CPU metrics
            if 'cpu_info' in metrics and not metrics['cpu_info'].get('error'):
                metrics_storage.store_cpu_metrics(metrics['cpu_info'])
            
            # Store memory metrics
            if 'memory_info' in metrics and not metrics['memory_info'].get('error'):
                metrics_storage.store_memory_metrics(metrics['memory_info'])
            
            # Store disk metrics
            if 'disk_info' in metrics and not metrics['disk_info'].get('error'):
                metrics_storage.store_disk_metrics(metrics['disk_info'])
            
            # Store network metrics
            if 'network_info' in metrics and not metrics['network_info'].get('error'):
                metrics_storage.store_network_metrics(metrics['network_info'])
            
            # Store load metrics
            if 'load_info' in metrics and not metrics['load_info'].get('error'):
                metrics_storage.store_load_metrics(metrics['load_info'])
            
            self.logger.debug("Successfully collected and stored metrics")
            
        except Exception as e:
            self.logger.error(f"Failed to collect and store metrics: {str(e)}")
    
    def collect_now(self):
        """Manually trigger a metrics collection."""
        self._collect_and_store_metrics()

# Global metrics collector instance
metrics_collector = MetricsCollector()
