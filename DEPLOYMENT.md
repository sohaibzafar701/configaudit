# ConfigAudit Deployment Guide

## Current Status

✅ Gunicorn configured and running on port 8004
✅ Systemd service enabled and auto-starting on reboot
✅ Nginx configured and serving the application
✅ Static files collected and served
⏳ SSL/HTTPS setup pending (requires DNS configuration)

## Service Management

### Gunicorn Service
```bash
# Check status
sudo systemctl status configaudit.service

# Start/Stop/Restart
sudo systemctl start configaudit.service
sudo systemctl stop configaudit.service
sudo systemctl restart configaudit.service

# View logs
sudo journalctl -u configaudit.service -f
tail -f /home/phisimuser/configaudit/logs/gunicorn_error.log
tail -f /home/phisimuser/configaudit/logs/gunicorn_access.log
```

### Nginx
```bash
# Test configuration
sudo nginx -t

# Reload configuration
sudo systemctl reload nginx

# View logs
sudo tail -f /var/log/nginx/error.log
sudo tail -f /var/log/nginx/access.log
```

## SSL Certificate Setup

### Prerequisites
1. DNS A records for `pdsconfigaudit.com` and `www.pdsconfigaudit.com` must point to `203.175.66.63`
2. Port 80 must be accessible from the internet (for Let's Encrypt validation)

### Steps to Enable SSL

1. **Install certbot** (if not already installed):
   ```bash
   sudo apt update
   sudo apt install certbot python3-certbot-nginx
   ```

2. **Obtain SSL certificate**:
   ```bash
   sudo certbot --nginx -d pdsconfigaudit.com -d www.pdsconfigaudit.com
   ```

3. **Certbot will automatically**:
   - Obtain the certificate from Let's Encrypt
   - Update the nginx configuration to enable HTTPS
   - Configure automatic redirect from HTTP to HTTPS
   - Set up auto-renewal

4. **Test auto-renewal**:
   ```bash
   sudo certbot renew --dry-run
   ```

5. **After SSL is configured**, the nginx config will be automatically updated by certbot. The HTTP server block will redirect to HTTPS, and the HTTPS server block will be uncommented and configured.

## Verification

### Test Gunicorn directly:
```bash
curl -I http://127.0.0.1:8004
```

### Test through Nginx (before SSL):
```bash
curl -I -H "Host: pdsconfigaudit.com" http://127.0.0.1
```

### Test through Nginx (after SSL):
```bash
curl -I https://pdsconfigaudit.com
```

## File Locations

- **Gunicorn config**: `/home/phisimuser/configaudit/gunicorn_config.py`
- **Systemd service**: `/etc/systemd/system/configaudit.service`
- **Nginx config**: `/etc/nginx/sites-available/configaudit`
- **Static files**: `/home/phisimuser/configaudit/staticfiles/`
- **Media files**: `/home/phisimuser/configaudit/media/`
- **Gunicorn logs**: `/home/phisimuser/configaudit/logs/`
- **Nginx logs**: `/var/log/nginx/`

## Troubleshooting

### Service won't start
- Check logs: `sudo journalctl -u configaudit.service -n 50`
- Verify port 8004 is free: `sudo lsof -i :8004`
- Check gunicorn config: `cat /home/phisimuser/configaudit/gunicorn_config.py`

### Nginx errors
- Test config: `sudo nginx -t`
- Check error log: `sudo tail -f /var/log/nginx/error.log`
- Verify nginx can read static files: `sudo ls -la /home/phisimuser/configaudit/staticfiles/`

### SSL certificate issues
- Ensure DNS is properly configured: `dig pdsconfigaudit.com`
- Verify port 80 is accessible: `sudo ufw status` (if firewall is enabled)
- Check certbot logs: `sudo tail -f /var/log/letsencrypt/letsencrypt.log`

## Notes

- The application is accessible via domain name only (not by IP directly)
- Direct IP access (`203.175.66.63`) will default to phishpds.com
- Gunicorn runs on internal port 8004 (not exposed externally)
- Nginx handles all external traffic and proxies to Gunicorn
