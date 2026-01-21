"""
Settings API endpoint
"""

import os
from pathlib import Path
from datetime import datetime
from services.database import DB_PATH

def handle_settings_request(handler, method):
    """Handle settings API requests"""
    if method == 'GET':
        parsed_path = handler.path.split('?')[0] if '?' in handler.path else handler.path
        
        if parsed_path.endswith('/backup'):
            return handle_backup_request(handler)
        elif parsed_path.endswith('/optimize'):
            return handle_optimize_request(handler)
        else:
            return {'error': 'Not found'}, 404
    
    elif method == 'POST':
        parsed_path = handler.path.split('?')[0] if '?' in handler.path else handler.path
        
        if parsed_path.endswith('/backup'):
            return handle_backup_request(handler)
        elif parsed_path.endswith('/optimize'):
            return handle_optimize_request(handler)
        else:
            return {'error': 'Not found'}, 404
    
    else:
        return {'error': 'Method not allowed'}, 405

def handle_backup_request(handler):
    """Handle database backup request"""
    try:
        if not DB_PATH.exists():
            return {'error': 'Database file not found'}, 404
        
        # Read database file
        with open(DB_PATH, 'rb') as f:
            db_content = f.read()
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'ncrt_backup_{timestamp}.db'
        
        # Send file response
        handler.send_response(200)
        handler.send_header('Content-Type', 'application/octet-stream')
        handler.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        handler.send_header('Content-Length', str(len(db_content)))
        handler.send_header('Cache-Control', 'no-cache')
        handler.end_headers()
        handler.wfile.write(db_content)
        handler.wfile.flush()
        
        # Return None to indicate response already sent
        return None
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {'error': f'Failed to create backup: {str(e)}'}, 500

def handle_optimize_request(handler):
    """Handle database optimization request (VACUUM)"""
    try:
        from services.database import get_db_connection
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Execute VACUUM command
        cursor.execute('VACUUM')
        
        conn.commit()
        conn.close()
        
        return {'message': 'Database optimized successfully'}, 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {'error': f'Failed to optimize database: {str(e)}'}, 500

