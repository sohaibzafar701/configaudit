# Page Display Specifications Plan

## Overview
This plan details what each page in the NCRT application should display, including current state, missing elements, and recommended improvements.

---

## 1. Home Page (`templates/index.html`)

### Current State
- ✅ Hero section with welcome message and CTA
- ✅ Statistics cards (Total Audits, Total Findings, Avg Compliance, Active Rules)
- ✅ Quick Actions section (4 action cards)
- ✅ Recent Activity list (last 10 audits)
- ✅ Current Audit Status (conditional display)
- ✅ Upload Configuration section (collapsible)
- ✅ Rule Selection Modal

### What Should Be Displayed

#### Hero Section
- **Purpose**: Welcome users and provide primary call-to-action
- **Content**:
  - Large title: "Network Configuration Rule Tester"
  - Tagline: Brief description of application purpose
  - Primary CTA button: "Start New Audit" (scrolls to upload section)
  - Optional: Brief feature highlights (3-4 bullet points with icons)

#### Statistics Dashboard
- **Purpose**: Provide at-a-glance overview of application usage
- **Content** (4 cards):
  1. **Total Audits**: Count of all completed audits
  2. **Total Findings**: Sum of all findings across all audits
  3. **Average Compliance**: Average compliance score across completed audits
  4. **Active Rules**: Count of enabled rules
- **Display**: Large numbers with icons, auto-refresh every 5 seconds
- **Data Source**: `/api/stats` endpoint

#### Quick Actions
- **Purpose**: Fast navigation to key features
- **Content** (4 cards with icons):
  1. **Upload Config**: Scrolls to upload section or opens upload modal
  2. **View Reports**: Links to `/templates/report.html`
  3. **Manage Rules**: Links to `/templates/rules.html`
  4. **View History**: Links to `/templates/report.html` (audit history section)
- **Display**: Icon cards with hover effects, clickable

#### Recent Activity
- **Purpose**: Show recent audit activity for quick access
- **Content**: List of last 10 audits showing:
  - Config file name
  - Status badge (Completed, Failed, Processing)
  - Timestamp (formatted)
  - Finding count
  - Device hostname (if available)
  - Quick link to view report
- **Display**: Clean list with badges, "View All" link to full history
- **Data Source**: `/api/stats` endpoint (recent_audits)

#### Current Audit Status (Conditional)
- **Purpose**: Show active audit progress prominently
- **Display When**: Audit status is Pending, Processing, or Partial
- **Content**:
  - Audit name/config file
  - Status badge
  - Progress bar with percentage
  - Current rule being executed
  - Rules completed/total (e.g., "15/25 rules")
  - "View Details" link to Audit page
  - Cancel button (if status allows)
- **Auto-refresh**: Every 2 seconds while active

#### Upload Configuration Section
- **Purpose**: Primary entry point for new audits
- **Content**:
  - Upload mode toggle (Single File / Batch Upload)
  - Drag-and-drop file upload area
  - File list display (for batch mode)
  - Supported formats notice
  - Upload button
  - Upload status messages
  - Batch progress (when processing multiple files)
- **Behavior**: Collapsible (default: collapsed if no active audit)
- **Features**: 
  - Drag-and-drop support
  - Multiple file selection
  - File validation (size, extension)
  - Rule selection modal integration

#### Rule Selection Modal
- **Purpose**: Allow users to select which rules to run
- **Content**:
  - Search input
  - Category filter dropdown
  - Rule list (grouped by category)
  - Select All / Deselect All buttons
  - Selected rule count
  - Cancel and Start Audit buttons
- **Display**: Modal overlay, shows before audit creation

---

## 2. Audit Page (`templates/audit.html`)

### Current State
- ✅ Current Audit section with status and progress
- ✅ Snapshots section
- ✅ Configuration Comparison section
- ⚠️ Missing: Device metadata display
- ⚠️ Missing: Detailed findings table
- ⚠️ Missing: Audit history/selection

### What Should Be Displayed

#### Current Audit Section
- **Purpose**: Show detailed information about the current/selected audit
- **Content**:
  - **Audit Information**:
    - Status badge (Pending, Processing, Completed, Failed, Cancelled)
    - Config file name
    - Device family (vendor + OS + model)
    - Created timestamp
    - Completed timestamp (if completed)
  - **Device Metadata** (if available):
    - Hostname
    - Model
    - Firmware version
    - Location
  - **Progress Display** (when Processing):
    - Progress bar (0-100%)
    - Current rule name being executed
    - Rules completed / Total rules
    - Progress percentage
    - Cancel button
  - **Findings Summary** (when Completed):
    - Total findings count
    - Breakdown by severity (Critical, High, Medium, Low, Info)
    - Quick link to full report
  - **Actions**:
    - "View Full Report" button (links to Report page)
    - "Create Snapshot" button (only if completed)
    - Cancel button (only if processing)

#### Configuration Snapshots Section
- **Purpose**: Manage audit snapshots for comparison
- **Display When**: Audit is completed and has snapshots OR user clicks "Create Snapshot"
- **Content**:
  - **Snapshot List Table**:
    - Snapshot ID
    - Snapshot name
    - Created timestamp
    - Status
    - Finding count
    - Actions: Compare, Delete
  - **Create Snapshot Button**: Opens modal to create new snapshot
  - **Create Snapshot Modal**:
    - Input field for snapshot name
    - Description of what snapshot includes
    - Create and Cancel buttons
- **Data Source**: `/api/audits?action=get_snapshots&audit_id=X`

#### Configuration Comparison Section
- **Purpose**: Compare two audits side-by-side
- **Display When**: At least 2 audits exist in history
- **Content**:
  - **Comparison Controls**:
    - Dropdown: Select Audit 1 (all audits + snapshots)
    - "vs" label
    - Dropdown: Select Audit 2 (all audits + snapshots)
    - "Compare" button
  - **Comparison Results** (after comparison):
    - **Header**: Shows which audits are being compared with labels
    - **Statistics**:
      - Added lines count
      - Removed lines count
      - Total changes count
    - **Diff View**:
      - Side-by-side or unified diff display
      - Color-coded: green for additions, red for removals
      - Line numbers
      - Scrollable view for large diffs
- **Data Source**: `/api/audits?action=compare_configs`

#### Missing Elements to Add
- **Device Metadata Card**: Display device information prominently
- **Findings Preview Table**: Show first 10 findings with expand option
- **Audit Selection**: Allow selecting different audits from history (not just current)

---

## 3. Rules Page (`templates/rules.html`)

### Current State
- ✅ Rules list display
- ✅ Filter by vendor and category
- ✅ Add New Rule button (not implemented)
- ⚠️ Missing: Rule details view
- ⚠️ Missing: Edit/Delete functionality
- ⚠️ Missing: Enable/Disable toggle
- ⚠️ Missing: Rule import/export

### What Should Be Displayed

#### Rules Management Header
- **Purpose**: Provide actions and filters
- **Content**:
  - "Add New Rule" button (opens rule creation modal/form)
  - Filter dropdown: Vendor (All Vendors, Cisco, Juniper, Arista, etc.)
  - Filter dropdown: Category (All Categories, Authentication, Encryption, etc.)
  - Filter dropdown: Rule Type (All Types, Pattern, Python, Hybrid)
  - Filter dropdown: Status (All, Enabled, Disabled)
  - Search input (search by name, description)
  - Import/Export buttons

#### Rules List/Table
- **Purpose**: Display all rules with key information
- **Content** (Table columns):
  1. **Checkbox**: For bulk actions
  2. **Name**: Rule name (clickable to view details)
  3. **Type**: Badge (Pattern, Python, Hybrid)
  4. **Category**: Category name
  5. **Severity**: Badge (Critical, High, Medium, Low, Info)
  6. **Status**: Enabled/Disabled toggle switch
  7. **Compliance**: List of compliance frameworks (badges)
  8. **Actions**: Edit, Delete, Test buttons
- **Display Options**:
  - Table view (default)
  - Card view (optional toggle)
  - Grouped by category (optional)
- **Features**:
  - Sortable columns
  - Pagination (if many rules)
  - Bulk enable/disable
  - Bulk delete

#### Rule Details View/Modal
- **Purpose**: View and edit rule details
- **Content** (when viewing/editing a rule):
  - **Basic Information**:
    - Name (editable)
    - Description (editable textarea)
    - Rule Type (dropdown: Pattern, Python, Hybrid)
    - Category (dropdown or text input)
    - Severity (dropdown)
    - Enabled toggle
  - **Rule Content**:
    - YAML content editor (code editor with syntax highlighting)
    - Preview/validation
    - Test button (test rule against sample config)
  - **Compliance**:
    - Compliance frameworks (multi-select or tags)
    - Framework mappings (JSON editor)
  - **Metadata**:
    - Created date
    - Last modified date
    - Tags (comma-separated)
    - Risk weight
  - **Actions**:
    - Save button
    - Cancel button
    - Delete button (with confirmation)
    - Test Rule button
    - Export Rule button

#### Add/Edit Rule Modal
- **Purpose**: Create or edit rules
- **Content**: Same as Rule Details View but in modal overlay
- **Features**:
  - Form validation
  - YAML syntax validation
  - Save and Cancel buttons

#### Import/Export Section
- **Purpose**: Backup and share rules
- **Content**:
  - **Export**:
    - Export all rules button
    - Export selected rules button
    - Export by category dropdown
    - Format selection (YAML, JSON)
  - **Import**:
    - File upload for rule import
    - Import options (replace, merge, skip duplicates)
    - Import button

---

## 4. Report Page (`templates/report.html`)

### Current State
- ✅ Audit history selection
- ✅ Search and filter controls
- ✅ Executive summary section
- ✅ Statistics section
- ✅ Charts section
- ✅ Compliance section
- ✅ Findings table
- ✅ Export modal
- ⚠️ Missing: Remediation tracking display
- ⚠️ Missing: Device metadata in report

### What Should Be Displayed

#### Audit History Selection
- **Purpose**: Select which audit to view
- **Content**:
  - **Audit History List**:
    - Checkbox for selection (multi-select for comparison)
    - Audit ID
    - Config file name
    - Device hostname (if available)
    - Status badge
    - Created timestamp
    - Finding count
    - Quick actions: View Report, Compare
  - **Actions**:
    - Refresh button
    - Compare Selected button (when 2 audits selected)
    - Clear selection button
- **Display**: Card-based list or table
- **Auto-select**: Most recent audit on page load

#### Search and Filter Section
- **Purpose**: Find specific findings quickly
- **Content**:
  - **Search Bar**:
    - Text input with placeholder
    - Clear button (×)
    - Search in: Rule name, Message, Config path
  - **Active Filters Display**:
    - Chips/badges showing active filters
    - Remove filter buttons
  - **Filter Controls**:
    - Severity filter (dropdown: All, Critical, High, Medium, Low, Info)
    - Category filter (dropdown: All Categories + list)
    - Rule Type filter (dropdown: All, Pattern, Python, Hybrid)
    - Tag filter (dropdown: All Tags + list)
    - Remediation Status filter (dropdown: All, Not Started, In Progress, Completed, Verified)
    - Group By (dropdown: None, Rule, Category, Severity, Config Path)
    - Sort By (dropdown: Severity, Rule Name, Category, Date)
    - Sort Order (dropdown: Ascending, Descending)
  - **Advanced Filters** (collapsible):
    - Rule name filter (text input)
    - Config path filter (text input)
    - Quick filter presets (Critical Only, High & Critical, Show All)
  - **Filter Actions**:
    - Apply Filters button
    - Clear Filters button
    - Export Report button
    - Print button

#### Executive Summary Section
- **Purpose**: High-level overview for management
- **Content**:
  - **Summary Text**:
    - Total findings count
    - Critical/High findings count
    - Overall risk assessment
    - Compliance status summary
    - Key recommendations
  - **Quick Stats**:
    - Risk score
    - Compliance score
    - Total rules executed
    - Rules passed/failed
- **Display**: Card with formatted text

#### Statistics Section
- **Purpose**: Visual breakdown of findings
- **Content**:
  - **Statistics Cards** (6 cards):
    1. Total Findings (large number)
    2. Critical (red badge, count)
    3. High (orange badge, count)
    4. Medium (yellow badge, count)
    5. Low (blue badge, count)
    6. Info (gray badge, count)
  - **Metrics Cards**:
    - Risk Score (0-100, color-coded)
    - Compliance Score (0-100, color-coded)
- **Display**: Grid layout, color-coded by severity

#### Charts Section
- **Purpose**: Visual representation of data
- **Content** (4 charts using Chart.js):
  1. **Severity Distribution Chart** (Pie/Doughnut):
     - Shows breakdown by severity
     - Color-coded segments
  2. **Category Breakdown Chart** (Bar):
     - Shows findings by category
     - Horizontal or vertical bars
  3. **Risk Heatmap Chart** (Heatmap):
     - Shows risk by category
     - Color intensity indicates risk level
  4. **Compliance Gauge Chart** (Gauge/Speedometer):
     - Shows compliance score
     - Color zones (red/yellow/green)
- **Display**: 2x2 grid, responsive

#### Compliance Section
- **Purpose**: Show compliance scores per framework
- **Content**:
  - **Framework Selector**:
    - Dropdown: All Frameworks, PCI-DSS, HIPAA, ISO 27001, NIST-CSF, CIS, SOX, GDPR
    - Refresh button
  - **Compliance Display** (when framework selected):
    - **Overall Score**: Large percentage display
    - **Score Breakdown**:
      - Total rules checked
      - Passed rules count
      - Failed rules count
    - **Requirements Breakdown** (table):
      - Requirement ID
      - Status (Passed/Failed/Not Applicable)
      - Passed rules count
      - Failed rules count
      - Total rules count
  - **Multi-Framework View** (when "All Frameworks" selected):
    - Grid of framework cards
    - Each card shows: Framework name, Score, Passed/Failed counts
- **Display**: Card-based layout

#### Findings Table
- **Purpose**: Detailed list of all findings
- **Content** (Table columns):
  1. **Expand/Collapse**: Arrow to show details
  2. **Severity**: Badge (color-coded)
  3. **Rule Name**: Clickable to rule details
  4. **Category**: Category badge
  5. **Message**: Finding message (truncated, expandable)
  6. **Config Path**: Path in configuration (clickable to highlight)
  7. **Remediation Status**: Badge (Not Started, In Progress, Completed, Verified)
  8. **Actions**: View Details, Update Remediation
- **Features**:
  - Expandable rows for details
  - Details show: Full message, Remediation steps, Remediation notes (editable), Compliance frameworks, Config path with context
  - Inline remediation status update
  - Inline remediation notes editing
  - Copy remediation command button
  - Grouping support (when Group By is selected)
  - Pagination (if many findings)
  - Export selected findings

#### Remediation Progress Section
- **Purpose**: Track remediation efforts
- **Content**:
  - **Progress Summary**:
    - Total findings requiring remediation
    - Not Started count
    - In Progress count
    - Completed count
    - Verified count
    - Progress percentage bar
  - **Remediation Status Filter**: Quick filter by status
- **Display**: Card with progress visualization

#### Export Modal
- **Purpose**: Configure report export
- **Content**:
  - **Format Selection**: Dropdown (PDF, CSV, JSON, HTML Standalone)
  - **Preset Selection**: Dropdown (Full Report, Executive Summary, Findings Only, Compliance Report, Custom)
  - **Include Sections** (checkboxes):
    - Statistics
    - Findings
    - Compliance
    - Charts
    - Executive Summary
  - **Filename Input**: Text field with default name
  - **Actions**: Export button, Cancel button

---

## 5. Settings Page (`templates/settings.html`)

### Current State
- ✅ Application Settings form
- ✅ Database Management section
- ✅ Advanced Settings section
- ⚠️ Missing: Settings persistence
- ⚠️ Missing: Settings API endpoint

### What Should Be Displayed

#### Application Settings Section
- **Purpose**: Configure application behavior
- **Content**:
  - **File Upload Settings**:
    - Maximum file size (MB) - number input with validation
    - Allowed file extensions - comma-separated text input
    - Help text explaining limits
  - **Audit Settings**:
    - Default rule selection - dropdown (All Enabled Rules, Prompt for Selection)
    - Auto-start audit after upload - checkbox
  - **Database & Retention**:
    - Audit retention (days) - number input (0 = keep forever)
    - Auto-cleanup old audits - checkbox
    - Warning about database size
  - **Export/Import Settings**:
    - Default export format - dropdown (HTML, PDF, CSV, JSON)
  - **Actions**:
    - Save Settings button
    - Reset to Defaults button
    - Export Settings button (download JSON)
    - Import Settings button (upload JSON)

#### Database Management Section
- **Purpose**: Monitor and manage database
- **Content**:
  - **Database Information** (read-only):
    - Database location - file path display
    - Database size - formatted size (MB/GB)
    - Total audits count
    - Total rules count
    - Last backup date (if available)
  - **Actions**:
    - Backup Database button (downloads database file)
    - Optimize Database button (runs VACUUM)
    - Clear Old Audits button (with confirmation, respects retention)
    - View Database Info button (shows detailed stats)

#### Advanced Settings Section
- **Purpose**: Advanced configuration options
- **Content** (collapsible, hidden by default):
  - **Performance Settings**:
    - Progress update interval (ms) - number input
    - Max concurrent rule execution - number input (currently 1, future feature)
  - **Debug Settings**:
    - Enable debug logging - checkbox
    - Log level - dropdown (Info, Warning, Error, Debug)
  - **UI Settings**:
    - Theme (if implemented) - dropdown
    - Items per page - number input
  - **Actions**:
    - Save Advanced Settings button

---

## 6. Help Page (`templates/help.html`)

### Current State
- ✅ Quick Start Guide
- ✅ Features Overview
- ✅ How-To Guides
- ✅ Understanding Findings
- ✅ FAQ
- ✅ Troubleshooting
- ✅ Complete and well-structured

### What Should Be Displayed

#### Quick Start Guide Section
- **Purpose**: Get users started quickly
- **Content**: Step-by-step guide (3 steps)
  1. Upload Configuration File
  2. Monitor Audit Progress
  3. Review Findings
- **Display**: Numbered list with links to relevant pages

#### Features Overview Section
- **Purpose**: Explain what each page does
- **Content**: Description of each page's features
  - Home Page features
  - Audit Page features
  - Rules Page features
  - Report Page features
- **Display**: Bulleted lists with links

#### How-To Guides Section
- **Purpose**: Detailed instructions for common tasks
- **Content**: Step-by-step guides for:
  - Uploading configurations
  - Creating rules
  - Viewing and exporting reports
  - Comparing configurations
  - Creating snapshots
- **Display**: Numbered lists with screenshots placeholders

#### Understanding Findings Section
- **Purpose**: Help users interpret results
- **Content**:
  - Severity levels explanation
  - Remediation status explanation
  - Compliance scores explanation
- **Display**: Definitions with examples

#### FAQ Section
- **Purpose**: Answer common questions
- **Content**: 8+ common questions with answers
- **Display**: Expandable accordion or simple Q&A format

#### Troubleshooting Section
- **Purpose**: Help users solve problems
- **Content**: Common issues and solutions:
  - Upload issues
  - Audit processing issues
  - Rule issues
  - Report issues
- **Display**: Problem-solution format

---

## Summary of Missing Elements

### Home Page
- ✅ Complete (all elements present)

### Audit Page
- ⚠️ Device metadata display (hostname, model, firmware, location)
- ⚠️ Findings preview table
- ⚠️ Audit selection dropdown (to view different audits)

### Rules Page
- ⚠️ Rule details view/modal
- ⚠️ Edit rule functionality
- ⚠️ Delete rule functionality
- ⚠️ Enable/Disable toggle per rule
- ⚠️ Rule import/export functionality
- ⚠️ Rule creation form/modal
- ⚠️ Rule testing interface

### Report Page
- ⚠️ Remediation progress summary section
- ⚠️ Device metadata in report header
- ✅ Mostly complete (minor enhancements needed)

### Settings Page
- ⚠️ Settings persistence (API endpoint needed)
- ⚠️ Settings load on page load
- ⚠️ Database backup functionality
- ⚠️ Database optimization functionality

### Help Page
- ✅ Complete (all elements present)

---

## Recommended Implementation Priority

### High Priority
1. **Rules Page**: Add rule creation, editing, and deletion functionality
2. **Audit Page**: Add device metadata display
3. **Settings Page**: Implement settings persistence

### Medium Priority
4. **Report Page**: Add remediation progress section
5. **Audit Page**: Add audit selection dropdown
6. **Rules Page**: Add import/export functionality

### Low Priority
7. **Settings Page**: Add database backup/optimize functionality
8. **All Pages**: Add loading states and error handling improvements

