"""
Gunicorn configuration file for ConfigAudit application
"""
import multiprocessing
import os

# Try to use decouple if available, otherwise use environment variables
try:
    from decouple import config as get_config
    def get_env(key, default):
        return get_config(key, default=default)
except ImportError:
    # Fallback to os.environ if decouple is not available
    def get_env(key, default):
        return os.environ.get(key, default)

# Server socket
bind = get_env('GUNICORN_BIND', '127.0.0.1:8004')
backlog = 2048

# Worker processes
workers_config = get_env('GUNICORN_WORKERS', 'auto')
if workers_config == 'auto':
    workers = multiprocessing.cpu_count() * 2 + 1
else:
    try:
        workers = int(workers_config)
    except ValueError:
        workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
try:
    timeout = int(get_env('GUNICORN_TIMEOUT', '30'))
except ValueError:
    timeout = 30
keepalive = 2

# Logging
default_access_log = os.path.join(os.path.dirname(__file__), "logs", "gunicorn_access.log")
default_error_log = os.path.join(os.path.dirname(__file__), "logs", "gunicorn_error.log")
accesslog = get_env('GUNICORN_ACCESS_LOG', default_access_log)
errorlog = get_env('GUNICORN_ERROR_LOG', default_error_log)
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "configaudit"

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL (if needed in future)
# keyfile = None
# certfile = None
