# Production Setup Guide

This guide will help you set up NCRT for production deployment.

## Prerequisites

- Python 3.8 or higher
- pip
- Virtual environment (recommended)
- PostgreSQL (optional, SQLite is default)

## Quick Setup

1. **Clone and navigate to the project:**
   ```bash
   cd /path/to/configaudit
   ```

2. **Create and activate virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the setup script:**
   ```bash
   ./scripts/setup_production.sh
   ```

   This script will:
   - Create `.env` file from `.env.example`
   - Generate a secure secret key
   - Create necessary directories
   - Set proper file permissions

5. **Review and update `.env` file:**
   ```bash
   nano .env  # or use your preferred editor
   ```

   **Critical settings to update:**
   - `SECRET_KEY` - Should be automatically generated, but verify it's not the default
   - `DEBUG=False` - Must be False in production
   - `ALLOWED_HOSTS` - Add your domain(s)
   - Database settings if using PostgreSQL

6. **Run migrations:**
   ```bash
   python3 manage.py migrate
   ```

7. **Collect static files:**
   ```bash
   python3 manage.py collectstatic --noinput
   ```

8. **Create superuser (if needed):**
   ```bash
   python3 manage.py createsuperuser
   ```

## Environment Variables

All configuration is done through the `.env` file. See `.env.example` for all available options.

### Critical Production Settings

```env
# Security
SECRET_KEY=<generated-secret-key>
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Database (if using PostgreSQL)
DATABASE_ENGINE=postgresql
DATABASE_NAME=ncrt_db
DATABASE_USER=ncrt_user
DATABASE_PASSWORD=<secure-password>
DATABASE_HOST=localhost
DATABASE_PORT=5432

# SSL/HTTPS (when using HTTPS)
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
SECURE_HSTS_SECONDS=31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS=True
SECURE_HSTS_PRELOAD=True
```

## Database Setup

### SQLite (Default)
No additional setup required. The database file will be created at `data/ncrt.db`.

### PostgreSQL (Recommended for Production)

1. **Install PostgreSQL:**
   ```bash
   sudo apt-get install postgresql postgresql-contrib  # Ubuntu/Debian
   ```

2. **Create database and user:**
   ```sql
   sudo -u postgres psql
   CREATE DATABASE ncrt_db;
   CREATE USER ncrt_user WITH PASSWORD 'your-secure-password';
   GRANT ALL PRIVILEGES ON DATABASE ncrt_db TO ncrt_user;
   \q
   ```

3. **Update `.env` file:**
   ```env
   DATABASE_ENGINE=postgresql
   DATABASE_NAME=ncrt_db
   DATABASE_USER=ncrt_user
   DATABASE_PASSWORD=your-secure-password
   DATABASE_HOST=localhost
   DATABASE_PORT=5432
   ```

4. **Install PostgreSQL adapter:**
   ```bash
   pip install psycopg2-binary
   ```

5. **Run migrations:**
   ```bash
   python3 manage.py migrate
   ```

## Running with Gunicorn

1. **Test Gunicorn:**
   ```bash
   gunicorn --config gunicorn_config.py auditconfig.wsgi:application
   ```

2. **Run as systemd service:**
   The `configaudit.service` file is provided. Update it with your paths and enable:
   ```bash
   sudo cp configaudit.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable configaudit
   sudo systemctl start configaudit
   ```

## Nginx Configuration

An example Nginx configuration is provided in `configaudit.nginx`. Update it with your domain and paths, then:

```bash
sudo cp configaudit.nginx /etc/nginx/sites-available/configaudit
sudo ln -s /etc/nginx/sites-available/configaudit /etc/nginx/sites-enabled/
sudo nginx -t  # Test configuration
sudo systemctl reload nginx
```

## SSL/HTTPS Setup

1. **Install Certbot:**
   ```bash
   sudo apt-get install certbot python3-certbot-nginx
   ```

2. **Obtain certificate:**
   ```bash
   sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
   ```

3. **Update `.env` file with SSL settings:**
   ```env
   SECURE_SSL_REDIRECT=True
   SESSION_COOKIE_SECURE=True
   CSRF_COOKIE_SECURE=True
   SECURE_HSTS_SECONDS=31536000
   SECURE_HSTS_INCLUDE_SUBDOMAINS=True
   SECURE_HSTS_PRELOAD=True
   ```

4. **Restart services:**
   ```bash
   sudo systemctl restart configaudit
   sudo systemctl restart nginx
   ```

## Security Checklist

- [ ] `SECRET_KEY` is generated and secure (not default)
- [ ] `DEBUG=False` in production
- [ ] `ALLOWED_HOSTS` includes only your domain(s)
- [ ] Database credentials are secure
- [ ] SSL/HTTPS is configured and enabled
- [ ] Security headers are enabled in `.env`
- [ ] File permissions are set correctly (`.env` should be 600)
- [ ] Regular backups are configured
- [ ] Logs are monitored
- [ ] Firewall rules are configured

## Monitoring and Logs

- Application logs: `logs/django.log`
- Gunicorn access logs: `logs/gunicorn_access.log`
- Gunicorn error logs: `logs/gunicorn_error.log`

Monitor these files regularly for errors and security issues.

## Backup Strategy

1. **Database backups:**
   ```bash
   # SQLite
   cp data/ncrt.db backups/ncrt_$(date +%Y%m%d_%H%M%S).db
   
   # PostgreSQL
   pg_dump -U ncrt_user ncrt_db > backups/ncrt_$(date +%Y%m%d_%H%M%S).sql
   ```

2. **Set up automated backups:**
   Create a cron job or systemd timer for regular backups.

## Troubleshooting

### Secret Key Generation
If the setup script doesn't generate a secret key:
```bash
python3 scripts/generate_secret_key.py
```
Then manually update `SECRET_KEY` in `.env`.

### Permission Errors
Ensure proper permissions:
```bash
chmod 600 .env
chmod 755 scripts/*.sh
```

### Database Connection Issues
- Verify database credentials in `.env`
- Check PostgreSQL is running: `sudo systemctl status postgresql`
- Test connection: `psql -U ncrt_user -d ncrt_db`

### Static Files Not Loading
```bash
python3 manage.py collectstatic --noinput
```
Ensure `STATIC_ROOT` in `.env` matches your Nginx configuration.

## Support

For issues or questions, refer to:
- Application documentation: `docs/APPLICATION_DOCUMENTATION.md`
- Deployment guide: `docs/DEPLOYMENT.md`
- DNS/Email setup: `docs/DNS_EMAIL_SETUP.md`
