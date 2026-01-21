# DNS and Email Authentication Setup Guide

## Domain: pdsconfigaudit.com
## Server IP: 203.175.66.63

---

## Part 1: Basic DNS Configuration

### Step 1: Access Your DNS Provider
Log in to your domain registrar or DNS hosting provider (e.g., GoDaddy, Namecheap, Cloudflare, AWS Route 53, etc.)

### Step 2: Add A Records

Add the following **A records** to point your domain to the server:

| Type | Name/Host | Value/Points To | TTL |
|------|-----------|-----------------|-----|
| A    | @         | 203.175.66.63   | 3600 (or default) |
| A    | www       | 203.175.66.63   | 3600 (or default) |

**Notes:**
- `@` represents the root domain (pdsconfigaudit.com)
- `www` represents www.pdsconfigaudit.com
- TTL (Time To Live) can be set to 3600 seconds (1 hour) or use your provider's default

### Step 3: Verify DNS Propagation

After adding the records, wait 5-60 minutes for DNS propagation, then verify:

```bash
# Check A record for root domain
dig pdsconfigaudit.com +short
# Should return: 203.175.66.63

# Check A record for www subdomain
dig www.pdsconfigaudit.com +short
# Should return: 203.175.66.63

# Or use nslookup
nslookup pdsconfigaudit.com
nslookup www.pdsconfigaudit.com
```

**Online Tools:**
- https://dnschecker.org/
- https://www.whatsmydns.net/

---

## Part 2: Email Authentication Records (SPF, DKIM, DMARC)

### Important Notes:
- These records are for **email authentication** and prevent email spoofing
- You need these **only if you plan to send emails** from this domain
- DKIM requires generating keys (usually done by your email service provider)
- If you're using a third-party email service (Gmail, SendGrid, Mailgun, etc.), they will provide the DKIM keys

---

## SPF (Sender Policy Framework) Record

### Purpose
Tells receiving mail servers which servers are authorized to send email for your domain.

### Record to Add

| Type | Name/Host | Value | TTL |
|------|-----------|-------|-----|
| TXT  | @         | `v=spf1 mx a ip4:203.175.66.63 ~all` | 3600 |

**Explanation:**
- `v=spf1` - SPF version 1
- `mx` - Allow mail servers listed in MX records
- `a` - Allow the domain's A record (203.175.66.63)
- `ip4:203.175.66.63` - Explicitly allow this IP address
- `~all` - Soft fail for all other sources (use `-all` for hard fail in production)

### Alternative SPF Records

**If using a third-party email service, you'll need to include them:**

**Example for SendGrid:**
```
v=spf1 include:sendgrid.net ip4:203.175.66.63 ~all
```

**Example for Mailgun:**
```
v=spf1 include:mailgun.org ip4:203.175.66.63 ~all
```

**Example for Google Workspace:**
```
v=spf1 include:_spf.google.com ip4:203.175.66.63 ~all
```

**Example if NOT sending email from this server:**
```
v=spf1 -all
```
(This tells mail servers that no one is authorized to send email from this domain)

---

## DKIM (DomainKeys Identified Mail) Record

### Purpose
Adds a digital signature to emails to verify they came from your domain and weren't tampered with.

### Important
DKIM requires:
1. **Generating a public/private key pair**
2. **Configuring your mail server** to sign emails with the private key
3. **Publishing the public key** in DNS

### Step 1: Generate DKIM Keys

**If using your own mail server (Postfix, etc.):**

```bash
# Install OpenSSL if not already installed
sudo apt install openssl

# Generate private key (keep this secure!)
openssl genrsa -out dkim_private.key 2048

# Generate public key
openssl rsa -in dkim_private.key -pubout -out dkim_public.key

# Extract the public key value (remove headers/footers and spaces)
cat dkim_public.key
```

**If using a third-party email service:**
- They will provide the DKIM keys and selector
- Common services:
  - **SendGrid**: Dashboard → Settings → Sender Authentication
  - **Mailgun**: Sending → Domain Settings → DKIM
  - **Google Workspace**: Admin Console → Apps → Google Workspace → Gmail → Authenticate email

### Step 2: Add DKIM TXT Record

| Type | Name/Host | Value | TTL |
|------|-----------|-------|-----|
| TXT  | `selector._domainkey` | `v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY_HERE` | 3600 |

**Example:**
```
Name: default._domainkey.pdsconfigaudit.com
Value: v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...
```

**Notes:**
- `selector` is a name you choose (common: `default`, `mail`, `dkim`, `20240121`)
- The public key (`p=`) should be one continuous string (no spaces, no line breaks)
- Remove `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----` from the key

### Common DKIM Selectors by Service:
- **SendGrid**: `s1._domainkey` and `s2._domainkey`
- **Mailgun**: `mailo._domainkey`
- **Google Workspace**: `google._domainkey`

---

## DMARC (Domain-based Message Authentication, Reporting & Conformance) Record

### Purpose
Tells receiving mail servers what to do with emails that fail SPF or DKIM checks, and where to send reports.

### Record to Add

| Type | Name/Host | Value | TTL |
|------|-----------|-------|-----|
| TXT  | `_dmarc` | `v=DMARC1; p=none; rua=mailto:dmarc@pdsconfigaudit.com; ruf=mailto:dmarc@pdsconfigaudit.com; fo=1` | 3600 |

### DMARC Policy Values

**Policy (`p=`):**
- `none` - Monitor only, don't reject (use for initial setup)
- `quarantine` - Send failed emails to spam folder
- `reject` - Reject emails that fail authentication (use after testing)

### Recommended DMARC Records by Stage

**Stage 1: Testing (Start Here)**
```
v=DMARC1; p=none; rua=mailto:dmarc@pdsconfigaudit.com; ruf=mailto:dmarc@pdsconfigaudit.com; fo=1; pct=100
```

**Stage 2: Quarantine (After monitoring)**
```
v=DMARC1; p=quarantine; rua=mailto:dmarc@pdsconfigaudit.com; ruf=mailto:dmarc@pdsconfigaudit.com; fo=1; pct=100
```

**Stage 3: Reject (Production)**
```
v=DMARC1; p=reject; rua=mailto:dmarc@pdsconfigaudit.com; ruf=mailto:dmarc@pdsconfigaudit.com; fo=1; pct=100
```

**Explanation:**
- `v=DMARC1` - DMARC version 1
- `p=none` - Policy: don't reject (monitoring mode)
- `rua=mailto:...` - Where to send aggregate reports
- `ruf=mailto:...` - Where to send forensic reports
- `fo=1` - Generate reports if either SPF or DKIM fails
- `pct=100` - Apply policy to 100% of emails

**Important:** Make sure the email address `dmarc@pdsconfigaudit.com` exists and can receive reports!

---

## Complete DNS Records Summary

Here's a complete list of all DNS records you should add:

| Type | Name/Host | Value | TTL |
|------|-----------|-------|-----|
| A    | @         | 203.175.66.63 | 3600 |
| A    | www       | 203.175.66.63 | 3600 |
| TXT  | @         | `v=spf1 mx a ip4:203.175.66.63 ~all` | 3600 |
| TXT  | `selector._domainkey` | `v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY` | 3600 |
| TXT  | `_dmarc`   | `v=DMARC1; p=none; rua=mailto:dmarc@pdsconfigaudit.com; ruf=mailto:dmarc@pdsconfigaudit.com; fo=1` | 3600 |

---

## Verification Steps

### 1. Verify DNS Records

```bash
# Check A records
dig pdsconfigaudit.com A +short
dig www.pdsconfigaudit.com A +short

# Check SPF
dig pdsconfigaudit.com TXT +short | grep spf

# Check DKIM
dig selector._domainkey.pdsconfigaudit.com TXT +short

# Check DMARC
dig _dmarc.pdsconfigaudit.com TXT +short
```

### 2. Online Verification Tools

**DNS Propagation:**
- https://dnschecker.org/
- https://www.whatsmydns.net/

**Email Authentication:**
- **SPF**: https://mxtoolbox.com/spf.aspx
- **DKIM**: https://mxtoolbox.com/dkim.aspx
- **DMARC**: https://mxtoolbox.com/dmarc.aspx
- **All-in-one**: https://mxtoolbox.com/SuperTool.aspx

**Comprehensive Email Test:**
- https://www.mail-tester.com/ (Send a test email and get a score)

---

## Common DNS Provider Instructions

### Cloudflare
1. Log in → Select domain
2. Go to **DNS** → **Records**
3. Click **Add record**
4. Select type, enter name and value
5. Click **Save**

### GoDaddy
1. Log in → **My Products** → **DNS**
2. Click **Add** under Records
3. Select type, enter name and value
4. Click **Save**

### Namecheap
1. Log in → **Domain List** → **Manage**
2. Go to **Advanced DNS** tab
3. Click **Add New Record**
4. Select type, enter host and value
5. Click **Save**

### AWS Route 53
1. Go to Route 53 → **Hosted zones**
2. Select your domain
3. Click **Create record**
4. Enter name, type, and value
5. Click **Create records**

---

## Troubleshooting

### DNS Not Propagating
- Wait 24-48 hours for full propagation
- Clear DNS cache: `sudo systemd-resolve --flush-caches` (Linux)
- Use different DNS servers: `dig @8.8.8.8 pdsconfigaudit.com`

### SPF Too Long
- SPF records have a 255 character limit per string
- Use `include:` mechanism to reference other SPF records
- Example: `v=spf1 include:_spf.google.com include:sendgrid.net ~all`

### DKIM Not Working
- Verify the selector name matches what your mail server uses
- Ensure public key has no spaces or line breaks
- Check that your mail server is signing emails with the matching private key

### DMARC Reports Not Received
- Ensure the email address exists and can receive mail
- Check spam folder
- Start with `p=none` to avoid blocking legitimate email

---

## Next Steps After DNS Configuration

1. **Wait for DNS propagation** (5-60 minutes typically)
2. **Verify all records** using the tools above
3. **Set up SSL certificate**:
   ```bash
   sudo certbot --nginx -d pdsconfigaudit.com -d www.pdsconfigaudit.com
   ```
4. **Test email sending** (if applicable)
5. **Monitor DMARC reports** for a few weeks before changing policy to `quarantine` or `reject`

---

## Need Help?

If you're unsure about:
- **Which email service you're using**: Check your Django settings for email backend configuration
- **DKIM selector**: Contact your email service provider or check their documentation
- **DMARC policy**: Start with `p=none` and monitor reports before tightening
