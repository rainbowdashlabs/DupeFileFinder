"""
Web-based GUI for the file duplicate scanner using Flask.
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import threading
import queue
import json
import sqlite3
from datetime import datetime
import subprocess
import platform

# Import our scanner functions
from file_duplicate_scanner import (
    create_database, scan_files, find_duplicates, normalize_path,
    ignore_duplicate_set, unignore_duplicate_set, print_database_stats, ScanStats
)

# Resolve project root and templates directory regardless of current working directory
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
TEMPLATES_DIR = os.path.join(PROJECT_ROOT, 'templates')

app = Flask(__name__, template_folder=TEMPLATES_DIR)
app.secret_key = 'file_scanner_secret_key'

# Global state
scan_status = {
    'running': False,
    'progress': 'Ready to scan',
    'output': [],
    'current_scan_id': None,
    'current_directory': None
}

scan_queue = queue.Queue()
duplicates_cache = []

@app.route('/')
def index():
    """Main page."""
    return render_template('index.html')

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    """Start a file scan."""
    global scan_status

    if scan_status['running']:
        return jsonify({'error': 'Scan already running'}), 400

    data = request.json
    scan_path = data.get('scan_path', '')
    db_path = data.get('db_path', 'file_scanner.db')
    include_hidden = data.get('include_hidden', False)
    excluded_dirs = data.get('excluded_dirs', [])

    if not scan_path:
        return jsonify({'error': 'Scan path is required'}), 400

    if not os.path.exists(scan_path):
        return jsonify({'error': 'Scan path does not exist'}), 400

    # Reset scan status
    scan_status = {
        'running': True,
        'progress': 'Starting scan...',
        'output': [],
        'current_scan_id': datetime.now().isoformat(),
        'current_directory': normalize_path(scan_path)
    }

    # Start scan in background thread
    scan_thread = threading.Thread(
        target=run_scan_background,
        args=(scan_path, db_path, include_hidden, excluded_dirs),
        daemon=True
    )
    scan_thread.start()

    return jsonify({'success': True, 'scan_id': scan_status['current_scan_id']})

@app.route('/api/scan_status')
def get_scan_status():
    """Get current scan status."""
    return jsonify(scan_status)

@app.route('/api/get_stats')
def get_stats():
    """Get database statistics."""
    db_path = request.args.get('db_path', 'file_scanner.db')

    if not os.path.exists(db_path):
        return jsonify({'error': 'Database file does not exist'}), 400

    try:
        conn = create_database(db_path)
        cursor = conn.cursor()

        # Total files
        cursor.execute('SELECT COUNT(*) FROM files')
        total_files = cursor.fetchone()[0]

        # Unique hashes
        cursor.execute('SELECT COUNT(DISTINCT sha1_hash) FROM files')
        unique_hashes = cursor.fetchone()[0]

        # Files with duplicates
        cursor.execute('''
            SELECT COUNT(*) FROM files 
            WHERE sha1_hash IN (
                SELECT sha1_hash FROM files 
                GROUP BY sha1_hash 
                HAVING COUNT(*) > 1
            )
        ''')
        duplicate_files = cursor.fetchone()[0]

        # Ignored duplicate sets
        cursor.execute('SELECT COUNT(*) FROM ignored_duplicates')
        ignored_sets = cursor.fetchone()[0]

        # Database file size
        db_size = os.path.getsize(db_path)
        db_size_mb = db_size / (1024 * 1024)

        # Recent scan activity
        cursor.execute('''
            SELECT COUNT(*) as count, DATE(scan_time) as scan_date
            FROM files 
            WHERE scan_time IS NOT NULL 
            GROUP BY DATE(scan_time) 
            ORDER BY scan_date DESC 
            LIMIT 7
        ''')
        recent_activity = cursor.fetchall()

        conn.close()

        storage_efficiency = ((unique_hashes/total_files)*100) if total_files > 0 else 0

        return jsonify({
            'success': True,
            'stats': {
                'total_files': total_files,
                'unique_files': unique_hashes,
                'duplicate_files': duplicate_files,
                'ignored_sets': ignored_sets,
                'storage_efficiency': round(storage_efficiency, 1),
                'database_size_mb': round(db_size_mb, 2),
                'recent_activity': recent_activity
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/load_duplicates')
def load_duplicates():
    """Load duplicates from database, filtered by current directory."""
    global duplicates_cache

    db_path = request.args.get('db_path', 'file_scanner.db')
    directory_filter = request.args.get('directory_filter', scan_status.get('current_directory'))
    include_ignored = request.args.get('include_ignored', 'false').lower() == 'true'

    if not os.path.exists(db_path):
        return jsonify({'error': 'Database file does not exist'}), 400

    try:
        conn = create_database(db_path)
        duplicates = find_duplicates(conn, directory_filter=directory_filter, include_ignored=include_ignored)
        conn.close()

        # Format duplicates for web display
        formatted_duplicates = []
        for i, (hash_value, file_paths) in enumerate(duplicates):
            duplicate_set = {
                'id': i,
                'hash': hash_value,
                'hash_short': hash_value[:16] + "...",
                'files': [],
                'ignored': False
            }

            for file_path in file_paths:
                file_info = {
                    'path': file_path,
                    'exists': os.path.exists(file_path),
                    'size': 'N/A',
                    'modified': 'N/A'
                }

                if file_info['exists']:
                    try:
                        file_info['size'] = format_file_size(os.path.getsize(file_path))
                        file_info['modified'] = datetime.fromtimestamp(
                            os.path.getmtime(file_path)
                        ).strftime('%Y-%m-%d %H:%M')
                    except Exception:
                        pass

                duplicate_set['files'].append(file_info)

            formatted_duplicates.append(duplicate_set)

        duplicates_cache = formatted_duplicates

        total_files = sum(len(dup['files']) for dup in formatted_duplicates)

        return jsonify({
            'duplicates': formatted_duplicates,
            'summary': {
                'duplicate_sets': len(formatted_duplicates),
                'total_files': total_files,
                'directory_filter': directory_filter,
                'include_ignored': include_ignored
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ignore_duplicate', methods=['POST'])
def ignore_duplicate():
    """Mark a duplicate set as ignored."""
    data = request.json
    sha1_hash = data.get('sha1_hash', '')
    db_path = data.get('db_path', 'file_scanner.db')

    if not sha1_hash:
        return jsonify({'error': 'SHA1 hash is required'}), 400

    if not os.path.exists(db_path):
        return jsonify({'error': 'Database file does not exist'}), 400

    try:
        conn = create_database(db_path)
        success = ignore_duplicate_set(conn, sha1_hash)
        conn.close()

        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Failed to ignore duplicate set'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unignore_duplicate', methods=['POST'])
def unignore_duplicate():
    """Remove a duplicate set from ignored list."""
    data = request.json
    sha1_hash = data.get('sha1_hash', '')
    db_path = data.get('db_path', 'file_scanner.db')

    if not sha1_hash:
        return jsonify({'error': 'SHA1 hash is required'}), 400

    if not os.path.exists(db_path):
        return jsonify({'error': 'Database file does not exist'}), 400

    try:
        conn = create_database(db_path)
        success = unignore_duplicate_set(conn, sha1_hash)
        conn.close()

        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Failed to unignore duplicate set'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete_file', methods=['POST'])
def delete_file():
    """Delete a specific file."""
    data = request.json
    file_path = data.get('file_path', '')

    if not file_path:
        return jsonify({'error': 'File path is required'}), 400

    if not os.path.exists(file_path):
        return jsonify({'error': 'File does not exist'}), 400

    try:
        os.remove(file_path)
        return jsonify({'success': True, 'message': f'File deleted: {file_path}'})
    except Exception as e:
        return jsonify({'error': f'Failed to delete file: {str(e)}'}), 500

@app.route('/api/open_file_location', methods=['POST'])
def open_file_location():
    """Open file location in system file manager."""
    data = request.json
    file_path = data.get('file_path', '')

    if not file_path:
        return jsonify({'error': 'File path is required'}), 400

    try:
        if platform.system() == "Windows":
            subprocess.run(["explorer", "/select,", file_path])
        elif platform.system() == "Darwin":  # macOS
            subprocess.run(["open", "-R", file_path])
        else:  # Linux
            parent_dir = os.path.dirname(file_path)
            subprocess.run(["xdg-open", parent_dir])

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': f'Failed to open file location: {str(e)}'}), 500

@app.route('/api/keep_only_file', methods=['POST'])
def keep_only_file():
    """Keep only one file and delete all others in the duplicate set."""
    data = request.json
    keep_file_path = data.get('file_path', '')
    duplicate_set_id = data.get('duplicate_set_id', -1)

    if not keep_file_path:
        return jsonify({'error': 'File path is required'}), 400

    if duplicate_set_id < 0 or duplicate_set_id >= len(duplicates_cache):
        return jsonify({'error': 'Invalid duplicate set ID'}), 400

    duplicate_set = duplicates_cache[duplicate_set_id]
    files_to_delete = [f['path'] for f in duplicate_set['files']
                      if f['path'] != keep_file_path and f['exists']]

    if not files_to_delete:
        return jsonify({'error': 'No files to delete'}), 400

    deleted_files = []
    errors = []

    for file_path in files_to_delete:
        try:
            os.remove(file_path)
            deleted_files.append(file_path)
        except Exception as e:
            errors.append(f"{file_path}: {str(e)}")

    return jsonify({
        'success': True,
        'deleted_count': len(deleted_files),
        'deleted_files': deleted_files,
        'errors': errors
    })

def run_scan_background(scan_path, db_path, include_hidden, excluded_dirs):
    """Run scan in background thread."""
    global scan_status

    try:
        # Create database connection
        conn = create_database(db_path)

        # Capture output
        original_print = print
        def capture_print(*args, **kwargs):
            message = " ".join(str(arg) for arg in args)
            scan_status['output'].append(message)
            if len(scan_status['output']) > 1000:  # Limit output length
                scan_status['output'] = scan_status['output'][-500:]

        # Replace print temporarily
        import builtins
        builtins.print = capture_print

        try:
            scan_status['progress'] = 'Scanning files...'
            files_processed = scan_files(
                scan_path,
                conn,
                include_hidden=include_hidden,
                excluded_dirs=excluded_dirs
            )

            scan_status['progress'] = f'Scan completed. {files_processed} files processed.'

        finally:
            builtins.print = original_print
            conn.close()

    except Exception as e:
        scan_status['output'].append(f"ERROR: {str(e)}")
        scan_status['progress'] = f'Scan failed: {str(e)}'

    finally:
        scan_status['running'] = False

def format_file_size(size_bytes):
    """Format file size in human readable format."""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

if __name__ == '__main__':
    print("Starting File Duplicate Scanner Web GUI...")
    print("Open your browser and go to: http://localhost:5000")
    app.run(debug=True, host='localhost', port=5000)
