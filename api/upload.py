"""
File upload API endpoint
"""

import os
import re
from pathlib import Path

UPLOAD_DIR = Path(__file__).parent.parent / "media"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Configuration
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB default
ALLOWED_EXTENSIONS = ['.txt', '.cfg', '.conf']

def handle_upload_request(handler, method):
    """Handle file upload requests (single or batch)"""
    if method == 'POST':
        content_type = handler.headers.get('Content-Type', '')
        
        if 'multipart/form-data' in content_type:
            content_length = int(handler.headers['Content-Length'])
            post_data = handler.rfile.read(content_length)
            
            # Parse multipart form data
            boundary = content_type.split('boundary=')[1].encode()
            parts = post_data.split(b'--' + boundary)
            
            uploaded_files = []
            
            for part in parts:
                if b'filename=' in part:
                    # Extract filename
                    header_part = part.split(b'\r\n\r\n')[0]
                    filename_match = re.search(rb'filename="([^"]+)"', header_part)
                    
                    if filename_match:
                        filename = filename_match.group(1).decode('utf-8')
                        
                        # Validate file extension
                        file_ext = Path(filename).suffix.lower()
                        if file_ext not in ALLOWED_EXTENSIONS:
                            uploaded_files.append({
                                'status': 'error',
                                'filename': filename,
                                'error': f'Invalid file extension. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'
                            })
                            continue
                        
                        # Extract file content
                        file_content = part.split(b'\r\n\r\n', 1)[1]
                        # Remove trailing boundary markers
                        file_content = file_content.rstrip(b'\r\n--')
                        
                        # Validate file size
                        if len(file_content) > MAX_FILE_SIZE:
                            uploaded_files.append({
                                'status': 'error',
                                'filename': filename,
                                'error': f'File exceeds maximum size of {MAX_FILE_SIZE / (1024*1024):.0f}MB'
                            })
                            continue
                        
                        # Validate file is not empty
                        if len(file_content.strip()) == 0:
                            uploaded_files.append({
                                'status': 'error',
                                'filename': filename,
                                'error': 'File is empty'
                            })
                            continue
                        
                        # Save file
                        file_path = UPLOAD_DIR / filename
                        with open(file_path, 'wb') as f:
                            f.write(file_content)
                        
                        # Read file content as text for processing
                        try:
                            config_content = file_content.decode('utf-8')
                        except UnicodeDecodeError:
                            config_content = file_content.decode('utf-8', errors='ignore')
                        
                        # Validate decoded content is not empty
                        if not config_content.strip():
                            uploaded_files.append({
                                'status': 'error',
                                'filename': filename,
                                'error': 'File content is empty after decoding'
                            })
                            continue
                        
                        # Extract device metadata (best effort)
                        from services.metadata_extractor import extract_metadata
                        metadata = extract_metadata(config_content)
                        
                        # Detect device family from parser
                        device_family = None
                        try:
                            from parsers.factory import create_parser
                            parser = create_parser(config_text=config_content)
                            if parser:
                                vendor_name = parser.__class__.__name__.lower().replace('parser', '')
                                device_family = vendor_name.capitalize()
                        except:
                            pass
                        
                        uploaded_files.append({
                            'status': 'uploaded',
                            'filename': filename,
                            'path': str(file_path),
                            'content': config_content,
                            'device_family': device_family,
                            'device_metadata': metadata
                        })
            
            # Check if any files were successfully uploaded
            successful_files = [f for f in uploaded_files if f.get('status') == 'uploaded']
            error_files = [f for f in uploaded_files if f.get('status') == 'error']
            
            # Return single file or batch
            if len(uploaded_files) == 1:
                file_result = uploaded_files[0]
                if file_result.get('status') == 'error':
                    return {'error': file_result.get('error', 'Upload failed'), 'filename': file_result.get('filename')}, 400
                return file_result, 200
            else:
                if not successful_files:
                    return {'error': 'All files failed to upload', 'files': uploaded_files}, 400
                return {
                    'status': 'uploaded',
                    'files': uploaded_files,
                    'count': len(successful_files),
                    'success_count': len(successful_files),
                    'error_count': len(error_files),
                    'errors': error_files
                }, 200
        
        return {'error': 'Invalid upload'}, 400
    
    return {'error': 'Method not allowed'}, 405

