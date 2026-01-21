"""
Timezone utility functions for formatting datetime according to user's timezone preference
"""

from datetime import datetime, timezone
try:
    from zoneinfo import ZoneInfo
except ImportError:
    # Fallback for Python < 3.9
    try:
        from backports.zoneinfo import ZoneInfo
    except ImportError:
        # Final fallback - use UTC only
        ZoneInfo = None


def get_timezone(timezone_str='UTC'):
    """
    Get a timezone object from a timezone string.
    
    Args:
        timezone_str: Timezone string (e.g., 'America/New_York', 'UTC', 'Europe/London')
    
    Returns:
        ZoneInfo timezone object, defaults to UTC if invalid
    """
    if ZoneInfo is None:
        return timezone.utc
    
    try:
        return ZoneInfo(timezone_str)
    except Exception:
        # If ZoneInfo fails (e.g., tzdata not installed), fall back to UTC
        try:
            return ZoneInfo('UTC')
        except Exception:
            # Final fallback to timezone.utc
            return timezone.utc


def format_datetime(dt, timezone_str='UTC', format_str='%Y-%m-%d %H:%M:%S'):
    """
    Format a datetime object according to the specified timezone and format.
    
    Args:
        dt: datetime object (naive or timezone-aware)
        timezone_str: Target timezone string (e.g., 'America/New_York')
        format_str: Python strftime format string
    
    Returns:
        Formatted datetime string
    """
    if dt is None:
        return 'Unknown'
    
    # Get timezone object
    tz = get_timezone(timezone_str)
    
    # If datetime is naive, assume it's UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    # Convert to target timezone
    dt_tz = dt.astimezone(tz)
    
    # Format according to format string
    return dt_tz.strftime(format_str)


def format_datetime_now(timezone_str='UTC', format_str='%Y-%m-%d %H:%M:%S'):
    """
    Get current datetime formatted according to the specified timezone and format.
    
    Args:
        timezone_str: Target timezone string (e.g., 'America/New_York')
        format_str: Python strftime format string
    
    Returns:
        Formatted datetime string
    """
    now = datetime.now(timezone.utc)
    return format_datetime(now, timezone_str, format_str)


def parse_datetime_format(format_str):
    """
    Convert JavaScript-style format string to Python strftime format.
    
    Args:
        format_str: JavaScript format string (e.g., 'YYYY-MM-DD HH:mm:ss')
    
    Returns:
        Python strftime format string
    """
    # Common format mappings
    format_map = {
        'YYYY': '%Y',
        'MM': '%m',
        'DD': '%d',
        'HH': '%H',
        'mm': '%M',
        'ss': '%S',
    }
    
    # Replace JavaScript format tokens with Python strftime tokens
    result = format_str
    for js_token, py_token in format_map.items():
        result = result.replace(js_token, py_token)
    
    return result


def format_datetime_from_iso(iso_string, timezone_str='UTC', format_str='%Y-%m-%d %H:%M:%S'):
    """
    Format an ISO datetime string according to the specified timezone and format.
    
    Args:
        iso_string: ISO format datetime string (e.g., '2024-01-15T14:30:00Z')
        timezone_str: Target timezone string (e.g., 'America/New_York')
        format_str: Python strftime format string
    
    Returns:
        Formatted datetime string
    """
    if not iso_string:
        return 'Unknown'
    
    try:
        # Parse ISO string
        if iso_string.endswith('Z'):
            dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
        elif '+' in iso_string or iso_string.count('-') > 2:
            # Has timezone info
            dt = datetime.fromisoformat(iso_string)
        else:
            # Naive datetime, assume UTC
            dt = datetime.fromisoformat(iso_string)
            dt = dt.replace(tzinfo=timezone.utc)
        
        return format_datetime(dt, timezone_str, format_str)
    except (ValueError, AttributeError) as e:
        # Fallback: try to parse as-is
        try:
            dt = datetime.fromisoformat(iso_string)
            return format_datetime(dt, timezone_str, format_str)
        except:
            return iso_string  # Return original if parsing fails

