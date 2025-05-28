# PortGuardian - Features Scratchpad

This document tracks potential features to implement in the PortGuardian application.

## Monitoring & Visualization Enhancements

- [x] **Real-time Graphs and Charts**
  - [x] Interactive charts showing CPU/memory usage over time
  - [ ] Network traffic visualizations for each port
  - [ ] Heat maps showing process resource consumption
  - [x] Implementation notes: Used Chart.js for frontend visualizations with metrics_storage.py backend

- [x] **System Health Dashboard**
  - [x] Overall system metrics (CPU, RAM, disk usage, network throughput)
  - [x] Temperature monitoring for critical components
  - [x] System uptime and load averages
  - [x] Implementation notes: Used psutil for backend data collection in utils/system_monitor.py

- [ ] **Notification System**
  - [ ] Email/SMS alerts when critical processes crash
  - [ ] Notifications when ports are opened/closed
  - [ ] Alerts for unusual network activity or resource spikes
  - [ ] Implementation notes: Consider using Flask-Mail for email notifications

## Security Features

- [ ] **Port Scanning Detection**
  - [ ] Monitor for port scanning attempts
  - [ ] Log and alert on suspicious connection patterns
  - [ ] Implement basic intrusion detection
  - [ ] Implementation notes: Track connection frequency and patterns

- [ ] **Enhanced Authentication**
  - [ ] Two-factor authentication
  - [ ] Role-based access control (admin vs. viewer)
  - [ ] LDAP/Active Directory integration
  - [ ] Implementation notes: Flask-Security could be useful here

- [x] **Audit Logging**
  - [x] Comprehensive logging of all actions
  - [x] User activity tracking
  - [x] Exportable audit reports
  - [x] Implementation notes: Used SQLite database to store logs with audit_logger.py

## Process Management

- [ ] **Process Scheduling**
  - [ ] Schedule process starts/stops
  - [ ] Implement automatic restarts for critical services
  - [ ] Create process dependencies
  - [ ] Implementation notes: Could use APScheduler for Python scheduling

- [ ] **Resource Limiting**
  - [ ] Set CPU/memory limits for specific processes
  - [ ] Implement process prioritization
  - [ ] Auto-kill processes exceeding resource thresholds
  - [ ] Implementation notes: Will require elevated privileges

- [x] **Process Grouping**
  - [x] Group related processes together
  - [x] Manage services as units
  - [x] Batch operations on process groups
  - [x] Implementation notes: Created process group model with SQLite database, pattern-based rules, and manual process assignment

## User Experience Improvements

- [x] **Dark Mode**
  - [x] Implement a dark theme option
  - [x] Allow customizable color schemes
  - [x] Save user preferences
  - [x] Implementation notes: Used CSS variables for theming in dark-theme.css

- [ ] **Mobile App**
  - [ ] Create a companion mobile application
  - [ ] Push notifications to mobile devices
  - [ ] Remote process management
  - [ ] Implementation notes: Consider React Native or Flutter

- [ ] **Customizable Dashboard**
  - [ ] Allow users to create custom views
  - [ ] Save favorite processes/ports for quick access
  - [ ] Implement drag-and-drop dashboard widgets
  - [ ] Implementation notes: Look into grid layout libraries like GridStack.js

## Advanced Features

- [x] **API Integration**
  - [x] RESTful API for programmatic access
  - [ ] Webhook support for integration with other tools
  - [x] API documentation with interactive interface
  - [x] Implementation notes: Implemented comprehensive REST API with authentication and documentation

- [ ] **Historical Data Analysis**
  - [ ] Store historical process/port data
  - [ ] Trend analysis and anomaly detection
  - [ ] Performance benchmarking
  - [ ] Implementation notes: Will need a database like PostgreSQL or TimescaleDB

- [ ] **Container/VM Support**
  - [ ] Monitor Docker containers
  - [ ] Track virtual machine processes
  - [ ] Kubernetes pod monitoring
  - [ ] Implementation notes: Docker SDK for Python

- [ ] **Network Traffic Analysis**
  - [ ] Packet inspection capabilities
  - [ ] Bandwidth monitoring by process
  - [ ] Traffic categorization (HTTP, DNS, etc.)
  - [ ] Implementation notes: May need libraries like pyshark or scapy

## Priority Implementation Order

1. System Health Dashboard - Quick win with high value
2. Dark Mode - Relatively simple to implement
3. Audit Logging - Important for security
4. Real-time Graphs and Charts - Enhances user experience
5. API Integration - Enables further integrations

## Implementation Notes

- All features should maintain the current permission-aware design
- Consider database migration to PostgreSQL for more advanced features
- Maintain responsive design for all new UI elements
