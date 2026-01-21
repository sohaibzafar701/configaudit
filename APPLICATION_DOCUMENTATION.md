# NCRT - Network Configuration Rule Tester
## Comprehensive Application Documentation

This document provides a complete overview of all workflows, fields, paths, and business logic in the NCRT application.

---

## Table of Contents

1. [Application Overview](#application-overview)
2. [Database Schema](#database-schema)
3. [Models and Data Structures](#models-and-data-structures)
4. [API Endpoints](#api-endpoints)
5. [Core Workflows](#core-workflows)
6. [Business Logic](#business-logic)
7. [Service Layer](#service-layer)
8. [Parsers](#parsers)
9. [Frontend Structure](#frontend-structure)

---

## Application Overview

**NCRT (Network Configuration Rule Tester)** is a desktop application for network device configuration security auditing. It analyzes router, switch, and firewall configurations from multiple vendors (Cisco, Juniper) to identify security vulnerabilities and compliance issues.

### Technology Stack
- **Backend**: Python 3.8+ (http.server)
- **Database**: SQLite (sqlite3)
- **Frontend**: HTML, CSS, JavaScript (vanilla)
- **Dependencies**: PyYAML, ciscoconfparse, reportlab

### Architecture
- **Server**: `server.py` - HTTP server on port 8001
- **API Layer**: `/api/*` endpoints
- **Service Layer**: Business logic services
- **Data Layer**: SQLite database in `data/ncrt.db`

---

## Database Schema

### Table: `rule`

Stores security audit rules that define what to check in configurations.

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| `id` | INTEGER | Primary key, auto-increment | PRIMARY KEY |
| `name` | TEXT | Rule name/identifier | NOT NULL |
| `description` | TEXT | Detailed rule description | |
| `rule_type` | TEXT | Type: 'pattern', 'python', 'hybrid' | NOT NULL |
| `category` | TEXT | Rule category (e.g., 'authentication', 'encryption') | |
| `severity` | TEXT | Default severity: 'critical', 'high', 'medium', 'low', 'info' | |
| `yaml_content` | TEXT | YAML-formatted rule content | |
| `tags` | TEXT | Comma-separated tags (e.g., 'cisco,generic') | |
| `enabled` | INTEGER | 1=enabled, 0=disabled | DEFAULT 1 |
| `remediation_template` | TEXT | Remediation guidance text | |
| `compliance_frameworks` | TEXT | Comma-separated frameworks (e.g., 'PCI-DSS,ISO27001') | |
| `framework_mappings` | TEXT | JSON mapping of frameworks to requirement IDs | |
| `risk_weight` | REAL | Risk weight multiplier (default 1.0) | DEFAULT 1.0 |
| `created_at` | TIMESTAMP | Creation timestamp | DEFAULT CURRENT_TIMESTAMP |

**Business Rules:**
- Rules with `tags` containing 'generic' or 'all' apply to all devices
- Rules with vendor-specific tags (e.g., 'cisco', 'juniper') apply only to matching devices
- Only `enabled=1` rules are executed during audits
- `yaml_content` structure varies by `rule_type`:
  - **pattern**: Contains `pattern` (regex) and optional `message`
  - **python**: Contains `python_code` or `python` field with executable code
  - **hybrid**: Contains both `pattern` and `python_code`

### Table: `audit`

Stores audit records for each configuration analysis.

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| `id` | INTEGER | Primary key, auto-increment | PRIMARY KEY |
| `status` | TEXT | Status: 'Pending', 'Processing', 'Completed', 'Failed', 'Cancelled', 'Partial' | NOT NULL |
| `device_identifier` | TEXT | Unique device identifier (user-provided) | |
| `device_family` | TEXT | Detected device family (e.g., 'Cisco IOS 16.9') | |
| `config_file` | TEXT | Original filename | |
| `parsed_config` | TEXT | JSON-encoded parsed configuration | |
| `created_at` | TIMESTAMP | Creation timestamp | DEFAULT CURRENT_TIMESTAMP |
| `completed_at` | TIMESTAMP | Completion timestamp | |
| `snapshot_name` | TEXT | Name if this is a snapshot | |
| `parent_audit_id` | INTEGER | ID of parent audit if snapshot | FOREIGN KEY |
| `device_hostname` | TEXT | Extracted hostname | |
| `device_model` | TEXT | Extracted device model | |
| `device_firmware` | TEXT | Extracted firmware version | |
| `device_location` | TEXT | Extracted location | |
| `device_make` | TEXT | Device manufacturer | |
| `device_type` | TEXT | Device type (Router, Switch, Firewall, etc.) | |
| `progress` | TEXT | JSON-encoded progress information | |

**Business Rules:**
- Status transitions: Pending → Processing → Completed/Failed/Cancelled
- `device_identifier` is required and used for asset tracking
- `parsed_config` stores JSON with structure: `{raw_ast: {...}, normalized: {...}, original: <config_text>}`
- Snapshots preserve audit state for comparison
- `progress` contains: `status`, `progress_percent`, `current_rule`, `total_rules`, `rules_completed`, `error`, `rule_findings`, `rule_errors`, `rule_execution_details`

### Table: `finding`

Stores individual security findings identified during audits.

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| `id` | INTEGER | Primary key, auto-increment | PRIMARY KEY |
| `audit_id` | INTEGER | Foreign key to audit | NOT NULL, FOREIGN KEY |
| `rule_id` | INTEGER | Foreign key to rule | NOT NULL, FOREIGN KEY |
| `severity` | TEXT | Finding severity | |
| `message` | TEXT | Finding description | |
| `config_path` | TEXT | Location in config (e.g., 'Line 123: interface GigabitEthernet0/1') | |
| `remediation` | TEXT | Remediation guidance | |
| `remediation_status` | TEXT | Status: 'Not Started', 'In Progress', 'Completed', 'Verified' | DEFAULT 'Not Started' |
| `remediation_notes` | TEXT | User notes on remediation | |
| `parent_finding_id` | INTEGER | ID of parent finding if child | FOREIGN KEY |

**Business Rules:**
- Parent-child structure: Multiple findings from same rule are grouped
- Parent finding has `parent_finding_id=NULL`, children reference parent
- Parent severity is highest severity of its children
- Only parent findings are counted in statistics
- Children provide detailed locations for grouped issues

---

## Models and Data Structures

### Rule Model (`models/rule.py`)

**Static Methods:**

#### `Rule.create(name, description, rule_type, category, severity, yaml_content, tags, remediation_template, compliance_frameworks, framework_mappings, risk_weight)`
Creates a new rule.
- **Parameters**: All rule fields
- **Returns**: `rule_id` (integer)
- **Business Logic**: Converts lists to comma-separated strings, JSON-encodes framework_mappings

#### `Rule.get_all(enabled_only=True)`
Gets all rules, optionally filtering by enabled status.
- **Returns**: List of rule dictionaries
- **Order**: Sorted by name

#### `Rule.get_by_id(rule_id)`
Gets a specific rule by ID.
- **Returns**: Rule dictionary or None

#### `Rule.get_by_category(category)`
Gets enabled rules by category.
- **Returns**: List of rule dictionaries

#### `Rule.get_by_tag(tag)`
Gets enabled rules matching a tag (LIKE search).
- **Returns**: List of rule dictionaries

#### `Rule.get_by_device_family(device_family)`
Gets rules applicable to a device family.
- **Logic**: 
  - Extracts vendor name from device_family (first word)
  - Returns rules with tags containing: 'generic', 'all', or the vendor name
- **Returns**: List of rule dictionaries

#### `Rule.get_by_tags(tags)`
Gets enabled rules matching any of the provided tags.
- **Parameters**: List of tag strings
- **Returns**: Deduplicated list of rule dictionaries

#### `Rule.get_all_tags(enabled_only=True)`
Gets all unique tags from rules.
- **Returns**: Sorted list of unique tag strings

#### `Rule.update(rule_id, **kwargs)`
Updates rule fields (in-place, no versioning).
- **Parameters**: `rule_id` and any field to update
- **Logic**: Only updates provided fields

#### `Rule.delete(rule_id)`
Deletes a rule.

### Audit Model (`models/audit.py`)

**Constants:**
- `STATUS_PENDING`, `STATUS_PROCESSING`, `STATUS_COMPLETED`, `STATUS_FAILED`, `STATUS_CANCELLED`, `STATUS_PARTIAL`

**Static Methods:**

#### `Audit.create(device_identifier, device_family, config_file, snapshot_name, parent_audit_id, device_hostname, device_model, device_firmware, device_location, device_make, device_type)`
Creates a new audit.
- **Required**: `device_identifier`
- **Status**: Set to 'Pending'
- **Returns**: `audit_id`

#### `Audit.get_by_id(audit_id)`
Gets audit by ID.

#### `Audit.get_current()`
Gets most recent audit.

#### `Audit.get_all(limit=None)`
Gets all audits, ordered by `created_at DESC`.

#### `Audit.update_status(audit_id, status)`
Updates audit status and `completed_at` timestamp.

#### `Audit.delete(audit_id)`
Deletes audit and all associated findings (cascade).

#### `Audit.delete_all()`
Deletes all audits and findings.

#### `Audit.create_snapshot(audit_id, snapshot_name)`
Creates a snapshot of an audit.
- **Logic**: Copies audit metadata, parsed_config, and all findings
- **Returns**: New `audit_id`

#### `Audit.get_snapshots(audit_id)`
Gets all snapshots for an audit.

#### `Audit.set_progress(audit_id, **progress_fields)`
Updates progress information.
- **Fields**: `status`, `progress_percent`, `current_rule`, `total_rules`, `rules_completed`, `error`, `rule_findings`, `rule_errors`, `rule_execution_details`
- **Storage**: JSON in `progress` column

#### `Audit.get_progress(audit_id)`
Gets current progress information.

#### `Audit.get_by_device_identifier(device_identifier)`
Gets all audits for a device identifier.

#### `Audit.get_latest_by_device_identifier(device_identifier)`
Gets most recent audit for a device.

#### `Audit.get_all_device_identifiers()`
Gets unique list of all device identifiers.

### Finding Model (`models/audit.py`)

**Static Methods:**

#### `Finding.create(audit_id, rule_id, severity, message, config_path, remediation, remediation_status, remediation_notes, parent_finding_id)`
Creates a finding.
- **Returns**: `finding_id`

#### `Finding.update_remediation(finding_id, status, notes)`
Updates remediation status and notes.

#### `Finding.get_by_audit(audit_id, include_children=True)`
Gets all findings for an audit.
- **Returns**: List with JOINed rule information
- **Order**: By `COALESCE(parent_finding_id, id), id`

#### `Finding.get_children(parent_finding_id)`
Gets child findings for a parent.

#### `Finding.get_parents(audit_id)`
Gets only parent findings (`parent_finding_id IS NULL`).

#### `Finding.get_grouped_by_audit(audit_id)`
Gets findings in parent-child structure.
- **Returns**: List of parent findings, each with `children` array

---

## API Endpoints

### Base URL
- Local: `http://localhost:8001`

### Request/Response Format
- All API requests: JSON
- All API responses: JSON (except PDF/CSV/HTML exports)
- Error responses: `{error: "message"}` with HTTP status codes

---

### `/api/audits` (GET)

**Query Parameters:**
- `history=true`: Get audit history
- `audit_id=<id>`: Get specific audit
- `timezone=<tz>`: Timezone for date formatting (default: UTC)
- `date_format=<format>`: Date format (default: YYYY-MM-DD HH:mm:ss)

**Responses:**

1. **History** (`?history=true`):
   - Returns: `{audits: [...]}`
   - Each audit includes: All fields + `finding_count`

2. **Specific Audit** (`?audit_id=<id>`):
   - Returns: Audit object with `findings` array

3. **Current Audit** (no params):
   - Returns: Most recent audit or `{}`

**Workflow:**
1. Parse query parameters
2. Apply timezone/date format preferences
3. Fetch audits from database
4. Add finding counts (for history)
5. Format dates according to preferences
6. Return JSON response

---

### `/api/audits` (POST)

**Request Body:** `{action: "<action>", ...}`

#### Action: `create`

**Request Body:**
```json
{
  "action": "create",
  "device_identifier": "10.28.9.34",
  "config_content": "...",
  "device_family": "Cisco IOS 16.9",
  "rule_tags": ["cisco", "authentication"],
  "device_make": "Cisco",
  "device_type": "Switch",
  "device_model": "Catalyst 9300",
  "config_file": "switch-config.txt"
}
```

**Validation:**
- `config_content` required, non-empty, max 10MB
- `device_identifier` required, non-empty
- `rule_tags` required, non-empty array
- Validates rules exist for selected tags

**Workflow:**
1. Validate input
2. Extract metadata from config (hostname, model, firmware, etc.)
3. Create audit record (status: 'Pending')
4. Start background thread for `process_audit()`
5. Return `{id: <audit_id>, status: 'created'}`

**Response:** `201 Created` with audit ID

---

#### Action: `delete`

**Request Body:**
```json
{
  "action": "delete",
  "audit_id": 123
}
```

**Workflow:**
- If `audit_id` provided: Delete specific audit
- If not: Delete all audits

**Response:** `200 OK`

---

#### Action: `get_progress`

**Request Body:**
```json
{
  "action": "get_progress",
  "audit_id": 123
}
```

**Response:**
```json
{
  "status": "Processing",
  "progress_percent": 45,
  "current_rule": "Check SSH Configuration",
  "total_rules": 100,
  "rules_completed": 45,
  "rule_execution_details": {...}
}
```

**Workflow:**
1. Fetch progress JSON from database
2. Merge with current status
3. Return progress object

---

#### Action: `cancel`

**Request Body:**
```json
{
  "action": "cancel",
  "audit_id": 123
}
```

**Workflow:**
- Updates audit status to 'Cancelled'
- Background process checks status and stops

---

#### Action: `update_remediation`

**Request Body:**
```json
{
  "action": "update_remediation",
  "finding_id": 456,
  "status": "In Progress",
  "notes": "Working on fix"
}
```

**Validation:**
- `status` must be one of: 'Not Started', 'In Progress', 'Completed', 'Verified'

---

#### Action: `create_snapshot`

**Request Body:**
```json
{
  "action": "create_snapshot",
  "audit_id": 123,
  "snapshot_name": "Before Remediation"
}
```

**Validation:**
- Audit must exist and be 'Completed'

**Workflow:**
1. Validate audit
2. Create new audit with snapshot name
3. Copy parsed_config
4. Copy all findings
5. Return new audit ID

---

#### Action: `compare_configs`

**Request Body:**
```json
{
  "action": "compare_configs",
  "audit_id1": 123,
  "audit_id2": 124
}
```

**Workflow:**
1. Fetch both audits
2. Extract original config text from parsed_config
3. Generate unified diff
4. Count changes (added/removed lines)
5. Return diff result

---

### `/api/rules` (GET)

**Paths:**
- `/api/rules`: Get all rules (including disabled)
- `/api/rules?category=<cat>`: Get rules by category
- `/api/rules/tags`: Get all unique tags
- `/api/rules/<id>`: Get specific rule

**Responses:**
- List of rules or single rule object

---

### `/api/rules` (POST)

**Actions:**

#### `create`
Creates a new rule.

#### `update`
Updates rule fields.

#### `delete`
Deletes a rule.

#### `test`
Tests a rule against sample config.
- **Request**: `{action: "test", rule_id: 123, config_content: "..."}`
- **Response**: `{rule: {...}, findings: [...], finding_count: N}`

#### `bulk_update`
Updates multiple rules at once.

---

### `/api/reports` (GET)

**Query Parameters:**
- `audit_id=<id>`: Audit ID (default: current)
- `format=html|pdf|csv|json|html_standalone`: Export format
- `severity=<sev>`: Filter by severity
- `category=<cat>`: Filter by category
- `sort_by=severity|rule_name|category`: Sort field
- `sort_order=asc|desc`: Sort order
- `group_by=rule|category|severity|config_path`: Group findings
- `sections=<list>`: Comma-separated sections (statistics, findings, compliance, charts, executive_summary)
- `preset=executive|findings_only|compliance|full`: Preset configurations
- `timezone=<tz>`: Timezone
- `date_format=<format>`: Date format

**Workflow:**
1. Parse query parameters
2. Fetch audit
3. Get filtered findings
4. Generate statistics/compliance if requested
5. Generate report in requested format:
   - **HTML**: Returns audit object with findings
   - **PDF**: Returns binary PDF file (special response handling)
   - **CSV**: Returns CSV text (special response handling)
   - **HTML_standalone**: Returns standalone HTML file
   - **JSON**: Returns JSON object with audit, findings, statistics

---

### `/api/upload` (POST)

**Content-Type:** `multipart/form-data`

**Workflow:**
1. Parse multipart form data
2. Validate each file:
   - Extension: `.txt`, `.cfg`, `.conf`
   - Size: Max 10MB
   - Non-empty content
3. Save to `media/` directory
4. Extract metadata (hostname, model, firmware, etc.)
5. Detect device family
6. Return file information

**Response:**
- Single file: File object
- Multiple files: `{status: "uploaded", files: [...], count: N}`

---

### `/api/stats` (GET)

**Query Parameters:**
- `timezone=<tz>`: Timezone
- `date_format=<format>`: Date format

**Response:**
```json
{
  "total_audits": 50,
  "total_findings": 1234,
  "average_compliance": 85.5,
  "active_rules": 150,
  "recent_audits": [...],
  "database_size": "2.5 MB",
  "database_size_bytes": 2621440
}
```

**Workflow:**
1. Count all audits
2. Sum all findings
3. Calculate average compliance for completed audits
4. Count enabled rules
5. Get recent 10 audits with finding counts
6. Get database file size
7. Return statistics

---

### `/api/assets` (GET)

**Paths:**
- `/api/assets`: Get all assets (device identifiers)
- `/api/assets/<device_identifier>`: Get all audits for device
- `/api/assets/<device_identifier>/latest`: Get latest audit for device

**Query Parameters:**
- `search=<query>`: Search device identifiers
- `timezone=<tz>`: Timezone
- `date_format=<format>`: Date format

**Response (list):**
```json
{
  "assets": [
    {
      "device_identifier": "10.28.9.34",
      "last_audit_date": "2024-01-15T10:30:00",
      "last_audit_date_formatted": "2024-01-15 10:30:00",
      "total_audits": 5,
      "latest_audit_status": "Completed",
      "latest_findings_count": 142,
      "latest_audit_id": 14,
      "device_hostname": "SWCAT-I9-IB-2",
      "device_model": "Catalyst 9300",
      ...
    }
  ],
  "count": 10
}
```

**Workflow:**
1. Get unique device identifiers
2. Filter by search query if provided
3. For each device:
   - Get all audits
   - Get latest audit
   - Count findings
   - Extract metadata
4. Sort by last audit date (descending)
5. Return asset list

---

## Core Workflows

### Workflow 1: Create and Execute Audit

**User Path:**
1. Navigate to Audit page (`/templates/audit.html`)
2. Upload configuration file OR paste config content
3. Enter device identifier
4. Select rule tags (e.g., 'cisco', 'authentication')
5. Optionally set device metadata (make, type, model)
6. Click "Start Audit"

**Backend Flow:**
1. **POST `/api/audits`** with `action: "create"`
2. **Validation**:
   - Config content non-empty, <10MB
   - Device identifier required
   - Rule tags selected
   - Rules exist for tags
3. **Metadata Extraction** (`services/metadata_extractor.py`):
   - Extract hostname (Cisco: `hostname X`, Juniper: `host-name X`)
   - Extract model (various patterns)
   - Extract firmware/version
   - Extract location (SNMP location)
   - Detect make (vendor)
   - Detect type (Router/Switch/Firewall)
4. **Create Audit Record**:
   - Status: 'Pending'
   - Store device metadata
5. **Start Background Thread**:
   - Call `process_audit(audit_id, config_content, device_family, None, selected_tags)`

**Processing Flow (`services/audit_service.py`):**
1. **Update Status**: 'Pending' → 'Processing'
2. **Parse Configuration**:
   - Create parser via factory (auto-detect or use provided device_family)
   - Parse config text → `{raw_ast: {...}, normalized: {...}, original: <text>}`
   - Store parsed_config as JSON in audit record
3. **Get Applicable Rules**:
   - If `selected_tags`: Get rules by tags
   - Filter by device_family (only rules with matching vendor tags or 'generic'/'all')
   - Only enabled rules
4. **Execute Rules** (for each rule):
   - Update progress (current_rule, rules_completed, progress_percent)
   - Execute rule based on type:
     - **pattern**: `execute_pattern_rule()`
     - **python**: `execute_python_rule()` (subprocess)
     - **hybrid**: `execute_hybrid_rule()`
   - Collect findings
   - Update progress with execution details
5. **Store Findings**:
   - Group findings by rule_id
   - Create parent-child structure:
     - Single finding → parent only
     - Multiple findings → parent + children
   - Parent severity = highest child severity
6. **Update Status**: 'Processing' → 'Completed'
7. **Update Progress**: progress_percent = 100%

**Progress Tracking:**
- Progress stored in `audit.progress` (JSON)
- Frontend polls `/api/audits` POST `get_progress`
- Progress includes: current_rule, rules_completed, total_rules, rule_execution_details

---

### Workflow 2: View Audit Results

**User Path:**
1. Navigate to Report page (`/templates/report.html`)
2. Select audit from dropdown (populated from audit history)
3. View statistics, findings, compliance scores
4. Apply filters (severity, category, search)
5. Group/sort findings
6. Export report (PDF, CSV, HTML, JSON)

**Backend Flow:**
1. **GET `/api/audits?history=true`**: Load audit list
2. **GET `/api/reports?audit_id=<id>`**: Load audit data
3. **GET `/api/reports?audit_id=<id>&format=pdf`**: Export PDF

**Report Generation (`services/report_generator.py`):**

#### Statistics Generation (`generate_statistics()`):
- Count parent findings only (not children)
- Severity breakdown (counts and percentages)
- Category breakdown
- Rule type breakdown
- **Risk Score Calculation**:
  - Base weights: critical=10, high=7, medium=4, low=2, info=1
  - Category weights: management=1.5, encryption=1.3, authentication=1.2, etc.
  - Path multiplier: 1.5 if management-related config path
  - Rule weight: from `rule.risk_weight`
  - Formula: `sum(finding_risk = base_weight × category_weight × path_multiplier × rule_weight)`
  - Normalized to 0-100 scale
  - Risk level: Critical (≥70), High (≥50), Medium (≥30), Low (<30)
- **Compliance Score**: Calls `calculate_compliance_score()`

#### Compliance Calculation (`calculate_compliance_score()`):
- Count parent findings only
- Only counts critical/high/medium severity as failures
- For each framework:
  - Get rules with framework tag
  - Count rules with findings (failures)
  - Score = (passed_rules / total_rules) × 100
  - Build requirements map from framework_mappings
  - Track requirement-level failures

#### Finding Filtering (`get_filtered_findings()`):
- Applies filters: severity, category, rule_type, rule_id, search, rule_name, config_path, tag
- Maintains parent-child structure
- Filters apply to parents and children independently
- Parent included if it matches OR has matching children
- Sorting: by severity (default), rule_name, category
- Grouping: by rule, category, severity, config_path

#### Export Formats:
- **PDF** (`generate_pdf_report()`): Uses ReportLab
  - Cover page with metadata
  - Executive summary (if included)
  - Statistics section
  - Findings table (first 100)
  - Compliance section
  - Page numbers
- **CSV** (`generate_csv_report()`): Comma-separated values
  - Metadata rows (if statistics included)
  - Header: Rule, Severity, Category, Message, Config Path, Remediation
  - Parent and child findings as separate rows (children indented)
- **HTML Standalone** (`generate_html_standalone_report()`): Complete HTML file
  - Cover page
  - Table of contents
  - All sections with styling
  - Print-friendly CSS
- **JSON**: Structured JSON object with all data

---

### Workflow 3: Rule Execution

**Rule Types:**

#### Pattern Rules (`execute_pattern_rule()`):
1. Parse YAML content → extract `pattern` (regex)
2. Search config text with regex
3. **Logic Types**:
   - **Negative Check** (rule name contains 'disabled' or 'no '):
     - Pattern found → Issue (security problem)
     - Create finding with severity
   - **Required Check** (rule name contains 'required'):
     - Check for negative pattern first (e.g., 'no aaa new-model')
     - If negative found → Issue
     - If pattern not found → Recommendation (low severity)
     - If pattern found → Info (configuration is good)
   - **Positive Check** (default):
     - Pattern found → Info (configuration matches)
     - Pattern not found → Recommendation (if 'required'/'enabled' in name)
4. **Finding Fields**:
   - `rule_id`: From rule
   - `severity`: From rule YAML or rule default
   - `message`: From rule YAML or rule description
   - `config_path`: `Line <N>: <matched_text>`
   - `matched_text`: Actual matched text
   - `line_number`: Line number in config
   - `context`: 3 lines before and after
   - `remediation`: From rule.remediation_template

#### Python Rules (`execute_python_rule()`):
1. Parse YAML content → extract `python_code`
2. Create temporary Python script file
3. Execute in subprocess with timeout (30 seconds)
4. Pass parsed_config as JSON to stdin
5. Script must output findings as JSON array
6. Expected finding format:
   ```json
   {
     "severity": "high",
     "message": "Issue description",
     "config_path": "Location",
     "remediation": "Fix guidance"
   }
   ```
7. Parse JSON output
8. Add rule_id and remediation to each finding
9. Clean up temporary file

#### Hybrid Rules (`execute_hybrid_rule()`):
1. Parse YAML → extract both `pattern` and `python_code`
2. Execute pattern part → get pattern findings
3. Execute Python part → get Python findings
4. Combine findings (mark source: 'pattern' or 'python')
5. If both found similar issues → mark as 'confirmed'

---

### Workflow 4: Asset Management

**User Path:**
1. Navigate to Assets page (`/templates/assets.html`)
2. View list of all devices (device identifiers)
3. See metadata: last audit date, status, finding count
4. Click device → view all audits for device
5. Click latest → view latest audit results

**Backend Flow:**
1. **GET `/api/assets`**: Get all device identifiers
2. For each device:
   - Get all audits (ordered by created_at DESC)
   - Get latest audit
   - Count findings
   - Extract metadata (hostname, model, firmware, etc.)
3. Return asset list sorted by last audit date

**Business Logic:**
- Asset = device_identifier (unique identifier)
- Multiple audits per asset (historical tracking)
- Latest audit represents current state
- Asset metadata from latest audit

---

### Workflow 5: Rule Management

**User Path:**
1. Navigate to Rules page (`/templates/rules.html`)
2. View all rules (table)
3. Filter by category, enabled status
4. Create new rule:
   - Enter name, description
   - Select rule type (pattern/python/hybrid)
   - Enter YAML content
   - Set category, severity, tags
   - Set compliance frameworks
   - Set remediation template
5. Edit existing rule
6. Enable/disable rule
7. Delete rule
8. Test rule against sample config

**Backend Flow:**
1. **GET `/api/rules`**: Get all rules
2. **POST `/api/rules`** with `action: "create"`: Create rule
3. **POST `/api/rules`** with `action: "update"`: Update rule
4. **POST `/api/rules`** with `action: "test"`: Test rule
   - Execute rule against sample config
   - Return findings preview

**Rule Tag System:**
- Tags: Comma-separated (e.g., 'cisco,authentication,management')
- Common tags: 'cisco', 'juniper', 'generic', 'all'
- Tag matching: LIKE search (`tags LIKE '%tag%'`)
- Device family matching:
  - Extract vendor from device_family (first word, lowercase)
  - Match rules with: vendor tag OR 'generic' OR 'all'

---

## Business Logic

### Rule Filtering Logic

**When executing audit:**
1. Start with selected tags OR all enabled rules
2. Filter by device_family:
   - Extract vendor name (first word of device_family, lowercase)
   - Include rules where tags contain:
     - Vendor name (e.g., 'cisco')
     - 'generic'
     - 'all'
3. Only include enabled rules (`enabled=1`)
4. Result: Rules applicable to the device

**Example:**
- Device: "Cisco IOS 16.9"
- Vendor: "cisco"
- Selected tags: ["authentication", "management"]
- Matches:
  - Rule with tags: "cisco,authentication" ✓
  - Rule with tags: "generic,authentication" ✓
  - Rule with tags: "juniper,authentication" ✗
  - Rule with tags: "all,management" ✓

---

### Finding Grouping Logic

**Parent-Child Structure:**
- **Single finding per rule**: Parent only (no children)
- **Multiple findings per rule**: 
  - Parent finding: `message = "{rule_name} ({count} instances)"`, `config_path = "Multiple locations"`, severity = highest
  - Child findings: Individual findings with specific locations

**Benefits:**
- Statistics count parents only (avoid double-counting)
- UI can expand/collapse groups
- Clearer organization

---

### Risk Score Calculation

**Formula:**
```
finding_risk = base_severity_weight × category_weight × path_multiplier × rule_weight
total_risk = sum(all finding_risks)
normalized_risk = (total_risk / max_possible_risk) × 100
```

**Weights:**
- **Severity**: critical=10, high=7, medium=4, low=2, info=1
- **Category**: management=1.5, encryption=1.3, authentication=1.2, access_control=1.2, firewall=1.1, vpn=1.15, default=1.0
- **Path Multiplier**: 1.5 if config_path contains management terms, else 1.0
- **Rule Weight**: From `rule.risk_weight` (default 1.0)

**Max Possible Score:**
- Per finding: 10 × 1.5 × 1.5 × 2.0 = 45
- Normalized to 0-100 scale

---

### Compliance Score Calculation

**Formula:**
```
compliance_score = (passed_rules / total_rules) × 100
```

**Rules:**
- Only counts parent findings (not children)
- Only critical/high/medium severity count as failures
- Only rules in framework's rule set count
- Requirements tracked via framework_mappings JSON

**Requirements Mapping:**
- Rule has `framework_mappings` JSON: `{"PCI-DSS": "Req 1.1", "ISO27001": "A.9.4.2"}`
- Requirement-level tracking: Count failures per requirement ID
- Requirement status: 'pass' if all rules pass, 'fail' if any fail

---

### Progress Tracking

**Progress Structure (JSON in `audit.progress`):**
```json
{
  "status": "executing_rules",
  "progress_percent": 45,
  "current_rule": "Check SSH Configuration",
  "total_rules": 100,
  "rules_completed": 45,
  "error": null,
  "rule_findings": [...],
  "rule_errors": [...],
  "rule_execution_details": {
    "rule_name": "Check SSH Configuration",
    "rule_id": 123,
    "rule_type": "pattern",
    "matched": true,
    "findings_count": 3,
    "execution_time_ms": 150,
    "details": [
      "Pattern rule: Searching for pattern 'ip ssh'",
      "⚠ MATCHED: Found 3 security issue(s)",
      "  ┌─ Finding #1 [HIGH]",
      "  │  Message: SSH not configured",
      "  │  Line number: 45",
      "  │  Location: Line 45: interface GigabitEthernet0/1",
      "  └─"
    ],
    "pattern_info": {
      "pattern": "ip ssh",
      "message": "SSH configuration check"
    },
    "config_sections": [...]
  },
  "rule_execution_history": [...]
}
```

**Update Frequency:**
- After each rule execution
- Frontend polls every 1-2 seconds during processing

---

### Configuration Parsing

**Parser Factory (`parsers/factory.py`):**
1. If vendor provided → get parser for vendor
2. If config_text provided → auto-detect:
   - Try each registered parser's `can_parse()` method
   - Return first match
3. Default: Cisco parser

**Parser Interface (`parsers/base.py`):**
- `parse(config_text)`: Returns `{raw_ast: {...}, normalized: {...}, original: <text>}`
- `detect_device_family(config_text)`: Returns device family string
- `get_vendor()`: Returns vendor name
- `can_parse(config_text)`: Returns True if config matches this parser

**Cisco Parser (`parsers/cisco/parser.py`):**
- **Detection**: Looks for Cisco indicators (hostname, interface, ip address, version)
- **Parsing**:
  - Extract hostname
  - Extract interfaces (sections starting with `interface`)
  - Extract access lists (sections starting with `ip access-list`)
  - Extract lines (console, vty sections)
  - Normalize: authentication, encryption, access_control
- **Device Family**: "Cisco IOS {version} ({hostname})"

**Juniper Parser (`parsers/juniper/parser.py`):**
- **Detection**: Looks for Juniper indicators (set version, set system host-name, JUNOS)
- **Parsing**:
  - Extract hostname (`set system host-name`)
  - Extract interfaces (`set interfaces`)
  - Extract firewall filters (`set firewall family`)
  - Extract system config
  - Normalize: authentication, encryption, access_control
- **Device Family**: "Juniper JunOS {version} ({hostname})"

---

### Metadata Extraction (`services/metadata_extractor.py`)

**Extraction Patterns:**

1. **Hostname**:
   - Cisco: `hostname <name>`
   - Juniper: `host-name <name>` or `set system host-name <name>`
   - Arista: `hostname <name>`

2. **Model**:
   - Cisco: `cisco <model> (revision)`, `WS-<model>`, `Catalyst <num>`, `Nexus <num>`
   - Juniper: `MX<num>`, `EX<num>`, `SRX<num>`, `chassis-type <model>`
   - Arista: `DCS-<model>`, `hardware model <model>`
   - Palo Alto: `PA-<num>`
   - Fortinet: `FortiGate-<num>`

3. **Firmware/Version**:
   - Cisco: `version <version>`
   - Juniper: `version <version>` or `JUNOS <version>`

4. **Location**:
   - SNMP: `snmp-server location <location>`
   - Comments: `! location: <location>`

5. **Make (Vendor)**:
   - Pattern matching on config text (cisco, juniper, arista, etc.)

6. **Type**:
   - Firewall: security-policy, firewall, nat rule
   - Switch: switchport, vlan, spanning-tree
   - Router: router ospf/bgp, routing-protocol
   - Wireless: wireless, wlan, ap group
   - Load Balancer: load balance, virtual-server, pool

---

## Service Layer

### `services/database.py`

**Functions:**
- `get_db_connection()`: Returns SQLite connection with Row factory
- `init_database()`: Creates tables, adds columns if missing, creates indexes
- `load_initial_rules()`: Placeholder for initial rule loading

**Schema Evolution:**
- Uses `ALTER TABLE` with try/except for backward compatibility
- Columns added incrementally: tags, remediation_template, compliance_frameworks, framework_mappings, risk_weight, progress, etc.

---

### `services/audit_service.py`

**Functions:**
- `process_audit(audit_id, config_content, device_family, selected_rule_ids, selected_tags)`: Main audit processing function
- `set_audit_progress()`, `get_audit_progress()`: Progress tracking helpers

**Process Flow:**
1. Validate config content
2. Update status to 'Processing'
3. Parse configuration
4. Get applicable rules
5. Execute rules (with progress tracking)
6. Store findings (parent-child structure)
7. Update status to 'Completed'

---

### `services/rule_engine.py`

**Functions:**
- `execute_rules(rules, parsed_config)`: Executes list of rules
- `execute_pattern_rule(rule, parsed_config)`: Pattern matching logic
- `execute_python_rule(rule, parsed_config)`: Python rule execution
- `execute_hybrid_rule(rule, parsed_config)`: Hybrid rule execution

**Pattern Rule Logic:**
- Negative checks: Pattern found = issue
- Required checks: Negative pattern found = issue, pattern not found = recommendation
- Positive checks: Pattern found = info

---

### `services/report_generator.py`

**Functions:**
- `get_filtered_findings(audit_id, filters, sort_by, sort_order, group_by)`: Filtered findings with parent-child structure
- `generate_statistics(audit_id)`: Statistics with risk score
- `calculate_compliance_score(audit_id, framework)`: Compliance score with requirements
- `generate_executive_summary(audit_id)`: Executive summary
- `generate_pdf_report(...)`: PDF generation (ReportLab)
- `generate_csv_report(...)`: CSV generation
- `generate_html_standalone_report(...)`: Standalone HTML
- `generate_comparison_report(audit_id1, audit_id2)`: Audit comparison

---

### `services/python_executor.py`

**Functions:**
- `execute_python_rule_safe(rule, parsed_config)`: Executes Python rule in subprocess

**Security:**
- Creates temporary script file
- Executes in subprocess (isolated)
- Timeout: 30 seconds
- Cleans up temp file
- Passes config as JSON via stdin
- Expects findings JSON on stdout

---

### `services/metadata_extractor.py`

**Functions:**
- `extract_metadata(config_text, device_family)`: Extracts all metadata fields

**Returns:**
```python
{
  'hostname': '...',
  'model': '...',
  'firmware': '...',
  'location': '...',
  'make': '...',
  'type': '...'
}
```

---

### `services/config_diff.py`

**Functions:**
- `compare_configs(audit_id1, audit_id2)`: Compares two audit configurations
- `get_config_summary(audit_id)`: Gets config summary (line counts, etc.)

**Diff Generation:**
- Uses Python `difflib.unified_diff`
- Returns: diff lines, diff text, statistics (added/removed lines)

---

### `services/timezone_utils.py`

**Functions:**
- `get_timezone(timezone_str)`: Gets timezone object (ZoneInfo or UTC fallback)
- `format_datetime(dt, timezone_str, format_str)`: Formats datetime with timezone
- `format_datetime_now(timezone_str, format_str)`: Formats current time
- `format_datetime_from_iso(iso_string, timezone_str, format_str)`: Formats ISO string
- `parse_datetime_format(format_str)`: Converts JavaScript format (YYYY-MM-DD) to Python format (%Y-%m-%d)

**Timezone Support:**
- Uses `zoneinfo` (Python 3.9+) or `backports.zoneinfo`
- Falls back to UTC if timezone not available
- Supports all IANA timezone names (e.g., 'America/New_York', 'Europe/London')

---

## Parsers

### Parser Registry (`parsers/registry.py`)

**Functions:**
- `register_parser(vendor, parser_class)`: Registers parser class
- `get_parser(vendor)`: Gets parser instance for vendor
- `get_all_parsers()`: Gets all registered parser classes
- `get_registered_vendors()`: Gets list of vendor names

**Auto-registration:**
- Cisco and Juniper parsers registered on import
- Extensible: Add new parsers by registering them

---

### Parser Base Class (`parsers/base.py`)

**Abstract Methods:**
- `parse(config_text)`: Must return `{raw_ast: {...}, normalized: {...}, original: <text>}`
- `detect_device_family(config_text)`: Must return device family string
- `get_vendor()`: Must return vendor name

**Parser Implementation Requirements:**
- Must implement all abstract methods
- Should implement `can_parse(config_text)` for auto-detection
- Normalized sections should focus on security-relevant domains

---

## Frontend Structure

### Pages (`templates/`)

1. **index.html**: Dashboard/Home page
   - Statistics cards
   - Quick actions
   - Recent audits

2. **audit.html**: Audit creation page
   - File upload or paste config
   - Device identifier input
   - Rule tag selection
   - Device metadata (optional)
   - Progress display during processing

3. **rules.html**: Rule management page
   - Rule list/table
   - Create/edit/delete rules
   - Enable/disable rules
   - Test rules
   - Filter by category

4. **report.html**: Report viewing page
   - Audit selection dropdown
   - Statistics display
   - Findings table (with parent-child expansion)
   - Filters (severity, category, search)
   - Grouping options
   - Sort options
   - Export buttons (PDF, CSV, HTML, JSON)
   - Charts (severity pie chart, category bar chart)

5. **assets.html**: Asset management page
   - Device list
   - Device metadata
   - Latest audit status
   - Finding counts
   - Audit history per device

6. **settings.html**: Settings page
   - Timezone selection
   - Date format selection
   - Other preferences

7. **help.html**: Help/documentation page

### JavaScript (`static/js/`)

- **main.js**: Main application logic, navigation
- **audit.js**: Audit page logic, file upload, progress polling
- **rules.js**: Rule management logic
- **report.js**: Report page logic, filtering, sorting, grouping
- **report-detail.js**: Detailed report view
- **assets.js**: Asset management logic
- **settings.js**: Settings management
- **common.js**: Shared utilities
- **analysis.js**: Analysis features
- **timezone-utils.js**: Timezone utilities (frontend)

### CSS (`static/css/`)

- **style.css**: Main stylesheet with all styling

---

## Summary

This application provides a comprehensive network configuration security auditing system with:

- **Multi-vendor support** (Cisco, Juniper, extensible)
- **Flexible rule system** (pattern, Python, hybrid)
- **Parent-child finding structure** for organized results
- **Advanced risk scoring** with multiple weight factors
- **Compliance tracking** with framework and requirement-level detail
- **Multiple export formats** (PDF, CSV, HTML, JSON)
- **Asset management** for device tracking
- **Progress tracking** with detailed execution information
- **Snapshot system** for audit comparison
- **Configuration comparison** between audits

All workflows, fields, and business logic are documented above. The system is designed for extensibility (new parsers, new rule types) while maintaining a clean architecture.

