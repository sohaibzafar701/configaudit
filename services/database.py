"""
Database connection and initialization
"""

import sqlite3
import json
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "ncrt.db"

def get_db_connection():
    """Get database connection"""
    # Ensure data directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row  # Enable column access by name
    return conn

def init_database():
    """Initialize database schema"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create Audit table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            status TEXT NOT NULL,
            device_family TEXT,
            config_file TEXT,
            parsed_config TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            snapshot_name TEXT,
            parent_audit_id INTEGER,
            device_hostname TEXT,
            device_model TEXT,
            device_firmware TEXT,
            device_location TEXT,
            device_make TEXT,
            device_type TEXT,
            FOREIGN KEY (parent_audit_id) REFERENCES audit(id)
        )
    """)
    
    # Create Finding table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS finding (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL,
            rule_id INTEGER NOT NULL,
            severity TEXT,
            message TEXT,
            config_path TEXT,
            FOREIGN KEY (audit_id) REFERENCES audit(id),
            FOREIGN KEY (rule_id) REFERENCES rule(id)
        )
    """)
    
    # Create Rule table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            rule_type TEXT NOT NULL,
            category TEXT,
            severity TEXT,
            yaml_content TEXT,
            tags TEXT,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Add tags column if it doesn't exist (for existing databases)
    try:
        cursor.execute("ALTER TABLE rule ADD COLUMN tags TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add remediation_template column if it doesn't exist
    try:
        cursor.execute("ALTER TABLE rule ADD COLUMN remediation_template TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add compliance_frameworks column if it doesn't exist
    try:
        cursor.execute("ALTER TABLE rule ADD COLUMN compliance_frameworks TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add framework_mappings column if it doesn't exist
    try:
        cursor.execute("ALTER TABLE rule ADD COLUMN framework_mappings TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add risk_weight column if it doesn't exist
    try:
        cursor.execute("ALTER TABLE rule ADD COLUMN risk_weight REAL DEFAULT 1.0")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add remediation column to finding if it doesn't exist
    try:
        cursor.execute("ALTER TABLE finding ADD COLUMN remediation TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add remediation status column to finding if it doesn't exist
    try:
        cursor.execute("ALTER TABLE finding ADD COLUMN remediation_status TEXT DEFAULT 'Not Started'")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add remediation notes column to finding if it doesn't exist
    try:
        cursor.execute("ALTER TABLE finding ADD COLUMN remediation_notes TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add parent_finding_id column to finding if it doesn't exist
    try:
        cursor.execute("ALTER TABLE finding ADD COLUMN parent_finding_id INTEGER")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Create index on parent_finding_id for efficient queries
    try:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_finding_parent_finding_id ON finding(parent_finding_id)")
    except sqlite3.OperationalError:
        pass  # Index might already exist
    
    # Add snapshot and metadata columns to audit if they don't exist
    for column in ['snapshot_name', 'parent_audit_id', 'device_hostname', 'device_model', 'device_firmware', 'device_location', 'device_make', 'device_type']:
        try:
            if column == 'parent_audit_id':
                cursor.execute(f"ALTER TABLE audit ADD COLUMN {column} INTEGER")
            else:
                cursor.execute(f"ALTER TABLE audit ADD COLUMN {column} TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
    
    # Add device_identifier column if it doesn't exist
    try:
        cursor.execute("ALTER TABLE audit ADD COLUMN device_identifier TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add progress column if it doesn't exist (stores JSON progress data)
    try:
        cursor.execute("ALTER TABLE audit ADD COLUMN progress TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Backfill device_identifier for existing audits (use config_file as default)
    try:
        cursor.execute("""
            UPDATE audit 
            SET device_identifier = COALESCE(device_identifier, config_file)
            WHERE device_identifier IS NULL
        """)
    except sqlite3.OperationalError:
        pass  # Column might not exist yet
    
    # Create index on device_identifier for fast lookups
    try:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_device_identifier ON audit(device_identifier)")
    except sqlite3.OperationalError:
        pass  # Index might already exist
    
    conn.commit()
    conn.close()
    
    # Load initial rules if database is empty
    load_initial_rules()

def load_initial_rules():
    """Load initial rules into database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if rules already exist
    cursor.execute("SELECT COUNT(*) FROM rule")
    if cursor.fetchone()[0] > 0:
        conn.close()
        return
    
    # TODO: Load initial rules from YAML files or data migration
    # For now, just create a placeholder
    print("Database initialized. Add initial rules as needed.")
    
    conn.close()

