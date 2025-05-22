/**
 * PortGuardian - Main JavaScript
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Add fade-in animation to cards
    document.querySelectorAll('.card').forEach(function(card) {
        card.classList.add('fade-in');
    });

    // Search functionality for tables
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('keyup', function() {
            const searchTerm = this.value.toLowerCase();
            const table = document.getElementById('portsTable');
            const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');

            for (let i = 0; i < rows.length; i++) {
                const rowText = rows[i].textContent.toLowerCase();
                if (rowText.includes(searchTerm)) {
                    rows[i].style.display = '';
                } else {
                    rows[i].style.display = 'none';
                }
            }
        });
    }

    // AJAX process kill functionality
    document.querySelectorAll('.kill-process-ajax').forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            const pid = this.getAttribute('data-pid');
            const processName = this.getAttribute('data-process');
            
            if (confirm(`Are you sure you want to terminate process "${processName}" (PID: ${pid})?`)) {
                fetch(`/kill/${pid}`, {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Show success message
                        const alertDiv = document.createElement('div');
                        alertDiv.className = 'alert alert-success alert-dismissible fade show';
                        alertDiv.innerHTML = `
                            ${data.message}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        `;
                        document.querySelector('.container').prepend(alertDiv);
                        
                        // Remove the row or update status
                        const row = this.closest('tr');
                        row.classList.add('table-danger');
                        setTimeout(() => {
                            row.remove();
                        }, 1000);
                    } else {
                        // Show error message
                        const alertDiv = document.createElement('div');
                        alertDiv.className = 'alert alert-danger alert-dismissible fade show';
                        alertDiv.innerHTML = `
                            ${data.message}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        `;
                        document.querySelector('.container').prepend(alertDiv);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred while trying to terminate the process.');
                });
            }
        });
    });

    // Auto-refresh data on dashboard
    const refreshData = function() {
        const dashboardTable = document.getElementById('portsTable');
        if (dashboardTable) {
            fetch('/api/ports')
                .then(response => response.json())
                .then(data => {
                    // Update table with new data
                    const tbody = dashboardTable.getElementsByTagName('tbody')[0];
                    tbody.innerHTML = '';
                    
                    data.forEach(port => {
                        const row = document.createElement('tr');
                        
                        // Port number
                        const portCell = document.createElement('td');
                        portCell.textContent = port.port;
                        row.appendChild(portCell);
                        
                        // Protocol
                        const protocolCell = document.createElement('td');
                        const protocolBadge = document.createElement('span');
                        protocolBadge.className = `badge ${port.protocol === 'TCP' ? 'bg-primary' : 'bg-success'}`;
                        protocolBadge.textContent = port.protocol;
                        protocolCell.appendChild(protocolBadge);
                        row.appendChild(protocolCell);
                        
                        // Status
                        const statusCell = document.createElement('td');
                        const statusBadge = document.createElement('span');
                        statusBadge.className = `badge ${port.status === 'LISTENING' ? 'bg-success' : 'bg-warning'}`;
                        statusBadge.textContent = port.status;
                        statusCell.appendChild(statusBadge);
                        row.appendChild(statusCell);
                        
                        // PID
                        const pidCell = document.createElement('td');
                        pidCell.textContent = port.pid;
                        row.appendChild(pidCell);
                        
                        // Process name
                        const processCell = document.createElement('td');
                        if (port.pid !== 'N/A') {
                            const processLink = document.createElement('a');
                            processLink.href = `/process/${port.pid}`;
                            processLink.className = 'process-link';
                            processLink.textContent = port.process_name;
                            processCell.appendChild(processLink);
                        } else {
                            processCell.textContent = port.process_name;
                        }
                        row.appendChild(processCell);
                        
                        // Start time
                        const startTimeCell = document.createElement('td');
                        startTimeCell.textContent = port.start_time;
                        row.appendChild(startTimeCell);
                        
                        // Actions
                        const actionsCell = document.createElement('td');
                        if (port.pid !== 'N/A') {
                            const btnGroup = document.createElement('div');
                            btnGroup.className = 'btn-group';
                            btnGroup.setAttribute('role', 'group');
                            
                            // Info button
                            const infoBtn = document.createElement('a');
                            infoBtn.href = `/process/${port.pid}`;
                            infoBtn.className = 'btn btn-sm btn-info';
                            infoBtn.innerHTML = '<i class="fas fa-info-circle"></i>';
                            btnGroup.appendChild(infoBtn);
                            
                            // Kill button
                            const killBtn = document.createElement('button');
                            killBtn.className = 'btn btn-sm btn-danger kill-process';
                            killBtn.setAttribute('data-pid', port.pid);
                            killBtn.setAttribute('data-process', port.process_name);
                            killBtn.innerHTML = '<i class="fas fa-times-circle"></i>';
                            btnGroup.appendChild(killBtn);
                            
                            actionsCell.appendChild(btnGroup);
                        } else {
                            const naSpan = document.createElement('span');
                            naSpan.className = 'text-muted';
                            naSpan.textContent = 'N/A';
                            actionsCell.appendChild(naSpan);
                        }
                        row.appendChild(actionsCell);
                        
                        tbody.appendChild(row);
                    });
                })
                .catch(error => console.error('Error refreshing data:', error));
        }
    };
    
    // Auto-refresh every 30 seconds if on dashboard
    if (document.getElementById('portsTable')) {
        setInterval(refreshData, 30000);
    }
});
