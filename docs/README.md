# NCRT - Network Configuration Rule Tester

A local desktop application for network device configuration security auditing.

## Features

- Analyze router, switch, and firewall configurations
- Multi-vendor support (Cisco, Juniper, Arista)
- Database-based rule management
- HTML/PDF report generation
- Simple HTML/CSS/JavaScript interface

## Installation

1. Install Python 3.8 or higher
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. **Windows Users - PDF Export**: If you want to use PDF export on Windows, you need to install GTK+ runtime libraries:
   - Download and install from: https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases
   - Or use the HTML export option instead (no additional dependencies required)
4. Run the application:
   ```
   python server.py
   ```
5. Open browser to http://localhost:8000

## Technology Stack

- **Backend**: Python 3.8+ (http.server)
- **Database**: SQLite (sqlite3 standard library)
- **Frontend**: HTML, CSS, JavaScript (vanilla)
- **Dependencies**: PyYAML, ciscoconfparse

## Usage

1. Start the server
2. Upload a configuration file
3. Select rules to run
4. View findings and generate reports

