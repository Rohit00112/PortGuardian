# PortGuardian

A Python Flask web application that provides a real-time overview of all open ports on the host machine. The platform displays the associated processes with each port and offers a feature to terminate (kill) those processes directly from the interface.

## Features

- **Home Dashboard**
  - Display a table of all listening/open ports
  - Show port number, protocol, status, PID, process name, command, and start time
  - Real-time refresh via AJAX
  - Kill processes directly from the dashboard

- **Detailed Process View**
  - Show detailed info about a selected process
  - Display CPU and memory usage
  - Show process tree (parent/child structure)
  - List all network connections

- **Process Termination**
  - Securely terminate processes
  - Confirmation dialog to prevent accidental termination
  - Logging of all termination actions

- **Security**
  - Basic authentication
  - Input sanitization
  - Confirmation for process termination

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/portguardian.git
   cd portguardian
   ```

2. Create a virtual environment and activate it:
   ```
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Run the application:
   ```
   python3 app.py
   ```

5. Access the application in your browser at `http://localhost:5001`

### Permission Requirements

On macOS and some Linux distributions, accessing detailed process and network information requires elevated privileges. If you encounter permission errors, you can run the application with sudo:

```
sudo python3 app.py
```

Alternatively, you can use system commands to view similar information:

```
# Show listening ports
lsof -i -P | grep LISTEN
netstat -an | grep LISTEN

# Show process details
ps -ef | grep <PID>
lsof -p <PID>
```

## Default Login

- Username: `admin`
- Password: `admin`

## Requirements

- Python 3.6+
- Flask
- psutil
- Flask-Login
- Flask-WTF

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool should be used responsibly. Terminating system processes can cause system instability. Use at your own risk.
