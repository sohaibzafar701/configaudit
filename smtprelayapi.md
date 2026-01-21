SMTP Relay API - Complete Project Analysis
Project Overview
The SMTP Relay API is a FastAPI-based service designed for phishing simulation platforms. It provides direct MX-to-MX email delivery with comprehensive monitoring, token-based authentication, and domain restrictions. The service acts as a secure email relay that bypasses traditional SMTP servers by directly connecting to recipient MX servers.

Technology Stack
Framework: FastAPI (Python 3.12+)
Database: SQLite with SQLAlchemy ORM (async)
SMTP Library: aiosmtplib for async SMTP operations
DNS Resolution: dnspython for MX record resolution
Authentication: JWT tokens (admin) + API tokens (domain-restricted)
Password Hashing: bcrypt via passlib
Background Processing: Asyncio-based queue system
Migrations: Alembic
Frontend: HTML/CSS/JavaScript (Alpine.js) for admin UI
Architecture Overview
High-Level Architecture
┌─────────────────┐
│  Phishing       │
│  Platform       │
└────────┬────────┘
         │ HTTP/HTTPS
         │ Bearer Token Auth
         ▼
┌─────────────────────────────────────┐
│      FastAPI Application            │
│  ┌───────────────────────────────┐  │
│  │   API Endpoints               │  │
│  │   - /api/v1/email/*           │  │
│  │   - /api/v1/tokens/*          │  │
│  │   - /api/v1/admin/*           │  │
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │   Authentication Middleware   │  │
│  │   - JWT (Admin)               │  │
│  │   - API Token (Domain Check)  │  │
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │   Background Queue Service    │  │
│  │   - 3 Worker Threads          │  │
│  │   - Async Email Processing    │  │
│  └───────────────────────────────┘  │
└────────┬────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│      Service Layer                  │
│  ┌───────────────────────────────┐  │
│  │   Email Service               │  │
│  │   - Email Composition         │  │
│  │   - SMTP Delivery             │  │
│  │   - Dry Run Handling          │  │
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │   DNS Service                 │  │
│  │   - MX Record Resolution      │  │
│  │   - Caching (TTL-based)       │  │
│  │   - Custom Overrides          │  │
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │   Auth Service                │  │
│  │   - Password Hashing          │  │
│  │   - JWT Generation            │  │
│  │   - API Token Management      │  │
│  └───────────────────────────────┘  │
└────────┬────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│      Data Layer                     │
│  ┌───────────────────────────────┐  │
│  │   SQLite Database             │  │
│  │   - Emails                    │  │
│  │   - API Tokens                │  │
│  │   - Admins                    │  │
│  │   - DNS Config                │  │
│  │   - MX Overrides              │  │
│  │   - Audit Logs                │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│      External Services              │
│  ┌───────────────────────────────┐  │
│  │   DNS Servers                 │  │
│  │   (MX Record Lookup)          │  │
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │   Recipient MX Servers        │  │
│  │   (Direct SMTP Delivery)      │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
Core Components
1. Database Models
Email Model (app/models/email.py)
Stores email metadata and delivery status
Fields: id, to, from_address, subject, body_html, body_text, attachments (JSON), mx_records (JSON), dry_run, dry_run_destination, status, created_at, sent_at, error_message, full_log
Status values: pending, processing, sent, failed
APIToken Model (app/models/token.py)
Manages API tokens with domain restrictions
Fields: id, token_hash (SHA256), name, allowed_domains (JSON array), created_at, last_used_at, is_active
Admin Model (app/models/admin.py)
Admin user accounts for web interface
Fields: id, username, password_hash (bcrypt), created_at, last_login, is_active
DNSConfig Model (app/models/dns_config.py)
Stores DNS server configuration
Fields: id, dns_servers (JSON array), updated_at, updated_by
MXOverride Model (app/models/mx_override.py)
Custom MX servers for specific domains
Fields: id, domain (unique), mx_servers (JSON array), priority, created_at
AuditLog Model (app/models/audit_log.py)
Complete audit trail of all operations
Fields: id, action, resource_type, resource_id, user_type, user_id, details, ip_address, user_agent, created_at, email_id (optional FK)
2. Service Layer
Email Service (app/services/email_service.py)
Responsibilities:

Compose MIME email messages (HTML/text, attachments)
Send emails via direct SMTP to MX servers
Handle dry run mode (alternate email or file save)
Retry logic across multiple MX servers
Key Methods:

compose_email(): Creates MIME multipart message
send_email_to_mx_server(): Direct SMTP connection to one MX server
send_email(): Main orchestration method with MX resolution and retry logic
_handle_dry_run(): Handles dry run mode (email redirect or file save)
Workflow:

Extract domain from recipient email
Resolve MX records (with custom overrides support)
Compose email message
Try each MX server in priority order until success
Log full SMTP conversation
Return success/failure with detailed logs
DNS Service (app/services/dns_service.py)
Responsibilities:

MX record resolution with caching
Custom DNS server support
Custom MX override handling
Domain extraction from email addresses
Key Methods:

resolve_mx_records(): Resolve MX records with caching (TTL-based)
resolve_mx_with_custom_overrides(): Check for custom MX servers first
extract_domain_from_email(): Extract domain from email address
clear_mx_cache(): Clear cache for specific domain or all
Caching Strategy:

In-memory cache with TTL (default 300 seconds)
Cache key: domain name
Cache invalidation: TTL expiration or manual clear
Auth Service (app/services/auth_service.py)
Responsibilities:

Password hashing/verification (bcrypt)
JWT token generation/verification (admin)
API token generation/verification (SHA256 hash)
Domain access validation
Key Methods:

hash_password() / verify_password(): Bcrypt operations
create_access_token() / verify_token(): JWT operations
generate_api_token(): Generate secure random token
hash_api_token(): SHA256 hash for storage
verify_api_token(): Verify token and update last_used_at
is_domain_allowed(): Check if domain is in token's allowed list
Queue Service (app/services/queue_service.py)
Responsibilities:

Background email processing queue
Worker thread management
Async task processing
Key Methods:

start_workers(): Start 3 background worker threads
stop_workers(): Gracefully stop all workers
queue_email(): Add email to processing queue
_worker(): Worker loop that processes emails
_process_email_task(): Process individual email task
get_queue_status(): Get queue metrics
Worker Process:

Worker waits for tasks in asyncio.Queue
On task receipt, updates email status to "processing"
Calls email_service.send_email()
Updates email record with results (status, logs, timestamps)
Handles errors gracefully
3. API Endpoints
Email API (app/api/v1/email.py)
POST /api/v1/email/send: Send email (requires API token)
GET /api/v1/email/status/{email_id}: Check delivery status
GET /api/v1/email/history: Get email history with pagination/filters
Send Email Flow:

Validate API token
Validate domain access (check if recipient domain is allowed)
Create email record in database (status: "pending")
Queue email for background processing
Return immediately with email_id and "processing" status
Token API (app/api/v1/tokens.py)
POST /api/v1/tokens: Create new API token (admin only)
GET /api/v1/tokens: List all tokens (admin only)
PUT /api/v1/tokens/{token_id}: Update token domains (admin only)
DELETE /api/v1/tokens/{token_id}: Revoke token (admin only)
GET /api/v1/tokens/{token_id}/domains: Get token domains (admin only)
Admin API (app/api/v1/admin.py)
POST /api/v1/admin/login: Admin authentication (returns JWT)
GET /api/v1/admin/dns-config: Get DNS configuration
PUT /api/v1/admin/dns-config: Update DNS servers
GET /api/v1/admin/mx-overrides: List MX overrides
POST /api/v1/admin/mx-overrides: Create MX override
PUT /api/v1/admin/mx-overrides/{id}: Update MX override
DELETE /api/v1/admin/mx-overrides/{id}: Delete MX override
GET /api/v1/admin/monitoring: Get statistics (24h, 7d, 30d)
GET /api/v1/admin/logs: Search email logs with filters
4. Authentication Middleware (app/middleware/auth.py)
Two Authentication Types:

Admin Authentication (JWT)
get_current_admin(): Validates JWT token, extracts admin_id, fetches admin from DB
Used for admin endpoints
API Token Authentication
get_current_api_token(): Validates API token (SHA256 hash lookup)
validate_domain_access(): Checks if recipient domain is in token's allowed_domains
Used for email endpoints
Security Flow:

Request → HTTPBearer → Extract Token → Verify Token → Get User/Token → Validate Access → Proceed
Business Logic & Workflow
Email Sending Workflow
1. Client Request
   ↓
2. API Token Validation
   ├─ Extract Bearer token
   ├─ Hash token (SHA256)
   ├─ Lookup in database
   └─ Check is_active
   ↓
3. Domain Access Validation
   ├─ Extract domain from recipient email
   ├─ Check if domain in token.allowed_domains
   └─ Reject if not allowed (403)
   ↓
4. Create Email Record
   ├─ Generate UUID
   ├─ Store in database (status: "pending")
   └─ Return email_id immediately
   ↓
5. Queue for Background Processing
   ├─ Add to asyncio.Queue
   └─ Return "processing" status
   ↓
6. Background Worker Picks Up Task
   ├─ Update status to "processing"
   ├─ Extract domain from recipient
   └─ Check for custom MX override
   ↓
7. MX Resolution
   ├─ If custom MX override exists → use it
   ├─ Else → resolve via DNS
   │   ├─ Check cache (TTL-based)
   │   ├─ If cache miss → query DNS servers
   │   └─ Cache results
   └─ Sort by priority (lowest = highest priority)
   ↓
8. Email Composition
   ├─ Create MIMEMultipart
   ├─ Add text/html parts
   ├─ Add attachments (base64 decode)
   └─ Set headers (From, To, Subject)
   ↓
9. Dry Run Check
   ├─ If dry_run = True
   │   ├─ If dry_run_destination contains '@'
   │   │   └─ Send to alternate email
   │   └─ Else
   │       └─ Save to file (.eml or .json)
   └─ Else → Continue to SMTP delivery
   ↓
10. SMTP Delivery (Try Each MX Server)
    ├─ For each MX server (priority order):
    │   ├─ Connect to MX server (port 25)
    │   ├─ Send EHLO
    │   ├─ Send message (MAIL FROM, RCPT TO, DATA)
    │   ├─ Log full SMTP conversation
    │   └─ If success → break loop
    └─ If all fail → mark as failed
    ↓
11. Update Email Record
    ├─ Status: "sent" or "failed"
    ├─ sent_at timestamp (if successful)
    ├─ full_log: Complete SMTP conversation
    ├─ mx_records: List of MX servers tried
    └─ error_message (if failed)
Domain Restriction Logic
Purpose: Ensure API tokens can only send emails to pre-approved domains.

Implementation:

Each API token has allowed_domains (JSON array)
On email send request:
Extract domain from recipient email (e.g., "user@example.com" → "example.com")
Check if domain exists in token.allowed_domains
Reject with 403 if not allowed
Example:

token.allowed_domains = ["example.com", "company.com"]
request.to = "user@example.com"  # ✅ Allowed
request.to = "user@evil.com"     # ❌ Rejected (403)
MX Resolution Logic
Priority Order:

Custom MX Override (if exists for domain)
Check mx_overrides table
Use custom MX servers directly
Skip DNS lookup
DNS Resolution (if no override)
Use configured DNS servers (or defaults: 8.8.8.8, 8.8.4.4, 1.1.1.1)
Query MX records for domain
Cache results (TTL: 300 seconds)
Sort by priority (lower number = higher priority)
SMTP Delivery
Try each MX server in priority order
Stop on first success
Only fail if all MX servers fail
Dry Run Mode
Purpose: Test email sending without actual delivery.

Modes:

Email Redirect: If dry_run_destination contains '@'
Send email to alternate address
Add X-Original-To header
Resolve MX for alternate domain
File Save: If dry_run_destination is file path or empty
Save to dry_run_emails/ directory
Format: .eml (MIME) or .json (structured)
Filename: email_{timestamp}_{recipient}.{ext}
Background Processing
Queue Architecture:

Queue Type: asyncio.Queue (in-memory)
Workers: 3 concurrent workers
Processing: Async/await (non-blocking)
Worker Lifecycle:

Start workers on application startup
Workers continuously poll queue (1s timeout)
On task receipt:
Fetch email record from database
Update status to "processing"
Call email service
Update with results
Stop workers gracefully on shutdown
Benefits:

Non-blocking API responses
Concurrent email processing
Better error handling
Queue status monitoring
Security Features
1. Token-Based Authentication
API Tokens: SHA256 hashed, domain-restricted
Admin Tokens: JWT with expiration (60 minutes default)
Token Storage: Only hash stored, never plaintext
2. Domain Restrictions
Each API token limited to specific domains
Validation on every email send request
Prevents unauthorized domain usage
3. Password Security
Bcrypt hashing for admin passwords
Salted hashes (via passlib)
No plaintext password storage
4. Input Validation
Pydantic schemas for all requests
Email format validation
Type checking and sanitization
5. Audit Logging
Complete audit trail in audit_logs table
Tracks: action, user, resource, IP, user agent
Links to emails when applicable
Configuration Management
Environment Variables (via .env)
Database:

DATABASE_URL: SQLite connection string
Security:

SECRET_KEY: JWT signing key
ALGORITHM: JWT algorithm (HS256)
ACCESS_TOKEN_EXPIRE_MINUTES: JWT expiration
Email:

DEFAULT_FROM_EMAIL: Default sender
SMTP_TIMEOUT: SMTP connection timeout (30s)
SMTP_RETRY_ATTEMPTS: Retry count (3)
DNS:

DEFAULT_DNS_SERVERS: Comma-separated DNS servers
DNS_TIMEOUT: DNS query timeout (5s)
MX_CACHE_TTL: Cache TTL in seconds (300)
Dry Run:

DRY_RUN_DEFAULT_DESTINATION: Default dry run destination
DRY_RUN_FORMAT: "eml" or "json"
Application:

DEBUG: Debug mode (false)
HOST: Bind address (0.0.0.0)
PORT: Listen port (8001)
Admin:

ADMIN_USERNAME: Default admin username
ADMIN_PASSWORD: Default admin password
Logging:

LOG_LEVEL: Logging level (INFO)
LOG_FORMAT: "json" or "text"
Database Schema
Tables
admins: Admin user accounts
api_tokens: API tokens with domain restrictions
emails: Email records and delivery status
attachments: Email attachments (FK to emails)
dns_config: DNS server configuration history
mx_overrides: Custom MX servers per domain
audit_logs: Complete audit trail
Relationships
emails ← attachments (one-to-many)
emails ← audit_logs (one-to-many, optional)
Indexes
emails.to, emails.status, emails.created_at
api_tokens.token_hash (unique)
admins.username (unique)
mx_overrides.domain (unique)
audit_logs.action, audit_logs.user_id, audit_logs.created_at
Admin Interface
Features
Dashboard: Real-time statistics (24h, 7d, 30d)
Token Management: Create, update, revoke API tokens
DNS Configuration: Configure DNS servers
MX Overrides: Set custom MX servers per domain
Log Viewer: Search and filter email logs with full SMTP conversation
Access
URL: /static/index.html
Authentication: JWT token (via /api/v1/admin/login)
Protected endpoints require Authorization: Bearer <jwt_token>
Deployment
Application Startup
Initialize database (create tables if needed)
Run Alembic migrations
Start background workers (3 workers)
Start FastAPI server (Uvicorn)
Mount static files for admin UI
Shutdown
Stop accepting new requests
Stop background workers (graceful)
Wait for queue to drain
Close database connections
Production Considerations
Use reverse proxy (nginx) for SSL termination
Process manager (systemd/supervisor)
Log rotation
Monitoring and alerting
Database backups (SQLite file)
Environment variable management
Key Design Decisions
Direct MX-to-MX Delivery: Bypasses traditional SMTP servers for direct delivery
Async Background Processing: Non-blocking API with queue-based processing
Domain Restrictions: Token-level domain whitelisting for security
Comprehensive Logging: Full SMTP conversation logs for debugging
Dry Run Support: Testing without actual delivery
Custom MX Overrides: Flexibility for testing/development
SQLite Database: Simple deployment, no external DB required
In-Memory Queue: Simple queue implementation (not persistent)
Data Flow Example
Scenario: Send email to user@example.com

1. Client → POST /api/v1/email/send
   Headers: Authorization: Bearer <api_token>
   Body: {to: "user@example.com", from: "sender@company.com", ...}

2. Middleware validates API token
   - Hash token → Lookup in database → Found

3. Domain validation
   - Extract domain: "example.com"
   - Check token.allowed_domains: ["example.com", "company.com"]
   - ✅ Allowed

4. Create email record
   - id: "uuid-123"
   - status: "pending"
   - Store in database

5. Queue email
   - Add to asyncio.Queue
   - Return: {email_id: "uuid-123", status: "processing"}

6. Background worker processes
   - Update status: "processing"
   - Check MX override: None
   - Resolve MX records:
     - Query DNS for "example.com"
     - Result: [(mail.example.com, 10), (backup.example.com, 20)]
     - Cache results

7. Compose email
   - Create MIMEMultipart
   - Add HTML/text content
   - Add attachments

8. SMTP delivery
   - Try mail.example.com:25
     - Connect ✅
     - EHLO ✅
     - MAIL FROM ✅
     - RCPT TO ✅
     - DATA ✅
     - Success! ✅

9. Update email record
   - status: "sent"
   - sent_at: 2024-01-01 12:00:00
   - full_log: "Connecting to mail.example.com...\nConnected..."
   - mx_records: ["mail.example.com"]

10. Client checks status
    - GET /api/v1/email/status/uuid-123
    - Response: {status: "sent", sent_at: "2024-01-01T12:00:00"}
Summary
The SMTP Relay API is a well-architected service that provides secure, direct email delivery for phishing simulation platforms. Key strengths include:

Security: Domain-restricted tokens, comprehensive authentication
Reliability: Retry logic, multiple MX server support, error handling
Observability: Full SMTP logs, audit trail, monitoring dashboard
Flexibility: Dry run mode, custom MX overrides, configurable DNS
Performance: Async processing, background queue, caching
The architecture follows separation of concerns with clear service boundaries, making it maintainable and extensible.