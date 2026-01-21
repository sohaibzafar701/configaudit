#!/usr/bin/env python3
"""
Verify .env configuration is correct
"""
import os
import sys
import django
from pathlib import Path

# Add project directory to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auditconfig.settings')
django.setup()

from django.conf import settings

print("=" * 50)
print("Configuration Verification")
print("=" * 50)
print(f"✓ DEBUG: {settings.DEBUG}")
print(f"✓ SECURE_SSL_REDIRECT: {settings.SECURE_SSL_REDIRECT}")
print(f"✓ SESSION_COOKIE_SECURE: {settings.SESSION_COOKIE_SECURE}")
print(f"✓ CSRF_COOKIE_SECURE: {settings.CSRF_COOKIE_SECURE}")
print(f"✓ SECURE_HSTS_SECONDS: {settings.SECURE_HSTS_SECONDS} ({settings.SECURE_HSTS_SECONDS/31536000:.1f} years)")
print(f"✓ SESSION_COOKIE_AGE: {settings.SESSION_COOKIE_AGE} seconds ({settings.SESSION_COOKIE_AGE/60} minutes)")
print(f"✓ SESSION_EXPIRE_AT_BROWSER_CLOSE: {settings.SESSION_EXPIRE_AT_BROWSER_CLOSE}")
print(f"✓ SESSION_SAVE_EVERY_REQUEST: {settings.SESSION_SAVE_EVERY_REQUEST}")
print()
print("=" * 50)
print("Session Behavior")
print("=" * 50)
if settings.SESSION_SAVE_EVERY_REQUEST:
    print("  - Session refreshes on each request")
    print("  - User stays logged in while active")
    print("  - 15-minute timeout applies to INACTIVITY only")
    print("  - Session expires when browser closes")
else:
    print("  - Session expires after exactly 15 minutes")
    print("  - Timeout applies regardless of activity")
    print("  - More secure but less user-friendly")
print()
print("=" * 50)
print("Security Notes")
print("=" * 50)
if settings.SECURE_SSL_REDIRECT:
    print("⚠️  SSL Redirect is ENABLED")
    print("   Ensure HTTPS is properly configured!")
    print("   Otherwise users will be redirected to non-existent HTTPS")
else:
    print("✓ SSL Redirect is disabled (OK if not using HTTPS yet)")
