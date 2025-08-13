
#!/usr/bin/env python3
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

app = Flask(__name__)
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
    # Create templates directory and HTML file
    create_html_template()
    print("Starting File Duplicate Scanner Web GUI...")
    print("Open your browser and go to: http://localhost:5000")
    app.run(debug=True, host='localhost', port=5000)

def create_html_template():
    """Create the HTML template file."""
    templates_dir = "templates"
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)

    html_content = '''<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Duplicate Scanner</title>
    <style>
        :root {
            --bg-primary: #36393f;
            --bg-secondary: #2f3136;
            --bg-tertiary: #292b2f;
            --bg-accent: #4f545c;
            --text-primary: #dcddde;
            --text-secondary: #b9bbbe;
            --text-muted: #72767d;
            --accent-color: #5865f2;
            --accent-hover: #4752c4;
            --success-color: #3ba55c;
            --danger-color: #ed4245;
            --warning-color: #faa61a;
            --info-color: #00b0f4;
            --border-color: #4f545c;
            --hover-bg: rgba(79, 84, 92, 0.16);
            --active-bg: rgba(79, 84, 92, 0.24);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Whitney', 'Helvetica Neue', Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            overflow-x: hidden;
        }

        .app-container {
            display: flex;
            height: 100vh;
        }

        .sidebar {
            width: 240px;
            background-color: var(--bg-secondary);
            display: flex;
            flex-direction: column;
            border-right: 1px solid var(--border-color);
        }

        .server-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--accent-color), #7289da);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 12px auto;
            font-weight: 600;
            font-size: 18px;
            color: white;
        }

        .channel-list {
            flex: 1;
            padding: 16px 8px;
        }

        .channel-category {
            color: var(--text-muted);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.02em;
            margin: 16px 8px 8px;
        }

        .channel {
            display: flex;
            align-items: center;
            padding: 8px 8px;
            margin: 2px 0;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.15s ease;
            color: var(--text-secondary);
        }

        .channel:hover {
            background-color: var(--hover-bg);
            color: var(--text-primary);
        }

        .channel.active {
            background-color: var(--active-bg);
            color: var(--text-primary);
        }

        .channel-icon {
            width: 20px;
            height: 20px;
            margin-right: 8px;
            opacity: 0.7;
        }

        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            background-color: var(--bg-primary);
        }

        .header {
            height: 48px;
            background-color: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            padding: 0 16px;
            box-shadow: 0 1px 0 rgba(4,4,5,0.2), 0 1.5px 0 rgba(6,6,7,0.05), 0 2px 0 rgba(4,4,5,0.05);
        }

        .header h1 {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
        }

        .header h1::before {
            content: "#";
            color: var(--text-muted);
            margin-right: 8px;
            font-weight: 300;
        }

        .content-area {
            flex: 1;
            overflow-y: auto;
            padding: 16px;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .card {
            background-color: var(--bg-secondary);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
            border: 1px solid var(--border-color);
        }

        .card-header {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 16px;
            color: var(--text-primary);
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--text-primary);
            font-size: 14px;
        }

        .form-input {
            width: 100%;
            padding: 10px 12px;
            background-color: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            color: var(--text-primary);
            font-size: 14px;
            transition: border-color 0.15s ease;
        }

        .form-input:focus {
            outline: none;
            border-color: var(--accent-color);
        }

        .form-input::placeholder {
            color: var(--text-muted);
        }

        .checkbox-wrapper {
            display: flex;
            align-items: center;
            margin: 8px 0;
        }

        .checkbox-wrapper input[type="checkbox"] {
            width: 20px;
            height: 20px;
            margin-right: 12px;
            accent-color: var(--accent-color);
        }

        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
        }

        .btn-primary {
            background-color: var(--accent-color);
            color: white;
        }

        .btn-primary:hover {
            background-color: var(--accent-hover);
        }

        .btn-success {
            background-color: var(--success-color);
            color: white;
        }

        .btn-success:hover {
            background-color: #2d7d32;
        }

        .btn-danger {
            background-color: var(--danger-color);
            color: white;
        }

        .btn-danger:hover {
            background-color: #c62828;
        }

        .btn-warning {
            background-color: var(--warning-color);
            color: white;
        }

        .btn-warning:hover {
            background-color: #ef6c00;
        }

        .btn-secondary {
            background-color: var(--bg-accent);
            color: var(--text-primary);
        }

        .btn-secondary:hover {
            background-color: #5d6269;
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .btn-group {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .status-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }

        .status-success {
            background-color: rgba(59, 165, 92, 0.1);
            color: var(--success-color);
        }

        .status-error {
            background-color: rgba(237, 66, 69, 0.1);
            color: var(--danger-color);
        }

        .status-warning {
            background-color: rgba(250, 166, 26, 0.1);
            color: var(--warning-color);
        }

        .status-info {
            background-color: rgba(0, 176, 244, 0.1);
            color: var(--info-color);
        }

        .log-container {
            background-color: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            height: 300px;
            overflow-y: auto;
            padding: 12px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
            line-height: 1.4;
        }

        .log-entry {
            margin-bottom: 4px;
            color: var(--text-secondary);
        }

        .log-entry.error {
            color: var(--danger-color);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }

        .stat-card {
            background-color: var(--bg-tertiary);
            padding: 16px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }

        .stat-value {
            font-size: 24px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 4px;
        }

        .stat-label {
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.02em;
        }

        .duplicate-set {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 12px;
            overflow: hidden;
            transition: all 0.2s ease;
        }

        .duplicate-set:hover {
            border-color: var(--text-muted);
        }

        .duplicate-header {
            padding: 16px;
            background-color: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background-color 0.15s ease;
        }

        .duplicate-header:hover {
            background-color: var(--hover-bg);
        }

        .duplicate-header.collapsed .toggle-icon {
            transform: rotate(-90deg);
        }

        .toggle-icon {
            transition: transform 0.2s ease;
            color: var(--text-muted);
        }

        .duplicate-content {
            max-height: 1000px;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }

        .duplicate-content.collapsed {
            max-height: 0;
        }

        .duplicate-file {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 16px;
        }

        .duplicate-file:last-child {
            border-bottom: none;
        }

        .file-info {
            flex: 1;
            min-width: 0;
        }

        .file-path {
            font-weight: 500;
            color: var(--text-primary);
            word-break: break-all;
            margin-bottom: 4px;
        }

        .file-meta {
            font-size: 12px;
            color: var(--text-muted);
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }

        .filter-section {
            background-color: var(--bg-tertiary);
            padding: 16px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            margin-bottom: 16px;
        }

        .filter-row {
            display: flex;
            gap: 12px;
            align-items: center;
            flex-wrap: wrap;
        }

        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 16px;
            border-radius: 4px;
            color: white;
            font-weight: 500;
            z-index: 1000;
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
            max-width: 400px;
        }

        .toast.show {
            opacity: 1;
            transform: translateX(0);
        }

        .toast.success {
            background-color: var(--success-color);
        }

        .toast.error {
            background-color: var(--danger-color);
        }

        .fade-out {
            opacity: 0;
            transform: translateX(-100%);
            max-height: 0;
            margin: 0;
            padding: 0;
            border: none;
        }

        .excluded-tag {
            display: inline-flex;
            align-items: center;
            background-color: var(--bg-accent);
            color: var(--text-primary);
            padding: 4px 8px;
            border-radius: 16px;
            font-size: 12px;
            margin: 2px;
        }

        .excluded-tag .remove {
            margin-left: 8px;
            cursor: pointer;
            color: var(--text-muted);
            font-weight: bold;
        }

        .excluded-tag .remove:hover {
            color: var(--danger-color);
        }

        .progress-bar {
            background-color: var(--bg-tertiary);
            border-radius: 4px;
            height: 8px;
            overflow: hidden;
            margin-top: 8px;
        }

        .progress-fill {
            background-color: var(--accent-color);
            height: 100%;
            transition: width 0.3s ease;
            border-radius: 4px;
        }

        /* Scrollbar styling */
        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-tertiary);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--bg-accent);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #5d6269;
        }

        /* Responsive design */
        @media (max-width: 768px) {
            .app-container {
                flex-direction: column;
            }
            
            .sidebar {
                width: 100%;
                height: auto;
                order: 2;
            }
            
            .main-content {
                order: 1;
            }
            
            .filter-row {
                flex-direction: column;
                align-items: stretch;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="server-icon">FS</div>
            
            <div class="channel-list">
                <div class="channel-category">Scanner</div>
                <div class="channel active" onclick="showTab('scan')" id="tab-scan">
                    <span class="channel-icon">🔍</span>
                    <span>Scan Configuration</span>
                </div>
                <div class="channel" onclick="showTab('duplicates')" id="tab-duplicates">
                    <span class="channel-icon">📋</span>
                    <span>Manage Duplicates</span>
                </div>
                
                <div class="channel-category">Monitoring</div>
                <div class="channel" onclick="showTab('logs')" id="tab-logs">
                    <span class="channel-icon">📄</span>
                    <span>Scan Logs</span>
                </div>
                <div class="channel" onclick="showTab('stats')" id="tab-stats">
                    <span class="channel-icon">📊</span>
                    <span>Statistics</span>
                </div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="main-content">
            <div class="header">
                <h1 id="header-title">Scan Configuration</h1>
            </div>

            <div class="content-area">
                <!-- Scan Configuration Tab -->
                <div id="scan-tab" class="tab-content active">
                    <div class="card">
                        <div class="card-header">Directory Settings</div>
                        
                        <div class="form-group">
                            <label class="form-label" for="scan-path">📂 Directory to Scan</label>
                            <input type="text" id="scan-path" class="form-input" placeholder="Enter directory path to scan">
                        </div>

                        <div class="form-group">
                            <label class="form-label" for="db-path">🗄️ Database File</label>
                            <input type="text" id="db-path" class="form-input" value="file_scanner.db" placeholder="Database file path">
                        </div>

                        <div class="checkbox-wrapper">
                            <input type="checkbox" id="include-hidden">
                            <label for="include-hidden">Include hidden files and directories</label>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">Exclusions</div>
                        
                        <div class="form-group">
                            <label class="form-label" for="exclude-dir">🚫 Exclude Directory</label>
                            <div style="display: flex; gap: 8px;">
                                <input type="text" id="exclude-dir" class="form-input" placeholder="Directory name or path to exclude">
                                <button class="btn btn-secondary" onclick="addExcludedDir()">Add</button>
                            </div>
                        </div>
                        
                        <div id="excluded-dirs" style="margin-top: 12px;"></div>
                    </div>

                    <div class="card">
                        <div class="card-header">Scan Control</div>
                        
                        <div class="btn-group">
                            <button class="btn btn-primary" id="start-scan" onclick="startScan()">▶️ Start Scan</button>
                            <button class="btn btn-danger" id="stop-scan" onclick="stopScan()" disabled>⏹️ Stop Scan</button>
                        </div>

                        <div id="scan-status" class="status-badge status-info" style="margin-top: 16px;">Ready to scan</div>
                    </div>
                </div>

                <!-- Duplicates Management Tab -->
                <div id="duplicates-tab" class="tab-content">
                    <div class="filter-section">
                        <div class="filter-row">
                            <div style="flex: 1;">
                                <label class="form-label" for="directory-filter">📂 Filter by Directory</label>
                                <input type="text" id="directory-filter" class="form-input" placeholder="Leave empty to show all">
                            </div>
                            <div class="checkbox-wrapper" style="margin-top: 20px;">
                                <input type="checkbox" id="include-ignored">
                                <label for="include-ignored">Show Ignored Sets</label>
                            </div>
                        </div>
                        
                        <div class="btn-group" style="margin-top: 16px;">
                            <button class="btn btn-primary" onclick="loadDuplicates()">📥 Load Duplicates</button>
                            <button class="btn btn-secondary" onclick="refreshDuplicates()">🔄 Refresh</button>
                            <button class="btn btn-success" onclick="expandAllSets()">📖 Expand All</button>
                            <button class="btn btn-secondary" onclick="collapseAllSets()">📕 Collapse All</button>
                        </div>
                        
                        <div id="duplicates-info" style="margin-top: 12px; color: var(--text-muted);">No duplicates loaded</div>
                    </div>

                    <div id="duplicates-container"></div>
                </div>

                <!-- Logs Tab -->
                <div id="logs-tab" class="tab-content">
                    <div class="card">
                        <div class="card-header">Scan Logs</div>
                        <div class="log-container" id="log-display"></div>
                    </div>
                </div>

                <!-- Statistics Tab -->
                <div id="stats-tab" class="tab-content">
                    <div class="card">
                        <div class="card-header">Database Statistics</div>
                        
                        <div class="stats-grid" id="stats-grid">
                            <div class="stat-card">
                                <div class="stat-value" id="stat-total-files">-</div>
                                <div class="stat-label">Total Files</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value" id="stat-unique-files">-</div>
                                <div class="stat-label">Unique Files</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value" id="stat-duplicate-files">-</div>
                                <div class="stat-label">Duplicate Files</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value" id="stat-ignored-sets">-</div>
                                <div class="stat-label">Ignored Sets</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value" id="stat-efficiency">-</div>
                                <div class="stat-label">Storage Efficiency</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value" id="stat-db-size">-</div>
                                <div class="stat-label">Database Size</div>
                            </div>
                        </div>
                        
                        <button class="btn btn-secondary" onclick="loadStats()">🔄 Refresh Statistics</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast notification container -->
    <div id="toast-container"></div>

    <script>
        let excludedDirs = [];
        let currentScanId = null;
        let scanStatusInterval = null;
        let currentDirectory = null;

        const tabTitles = {
            'scan': 'Scan Configuration',
            'duplicates': 'Manage Duplicates', 
            'logs': 'Scan Logs',
            'stats': 'Statistics'
        };

        function showToast(message, type = 'success') {
            const toastContainer = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.textContent = message;
            
            toastContainer.appendChild(toast);
            
            setTimeout(() => toast.classList.add('show'), 100);
            
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => toastContainer.removeChild(toast), 300);
            }, 3000);
        }

        function showTab(tabName) {
            // Update sidebar
            document.querySelectorAll('.channel').forEach(ch => ch.classList.remove('active'));
            document.getElementById(`tab-${tabName}`).classList.add('active');
            
            // Update content
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            document.getElementById(`${tabName}-tab`).classList.add('active');
            
            // Update header
            document.getElementById('header-title').textContent = tabTitles[tabName];
            
            // Load data for specific tabs
            if (tabName === 'stats') {
                loadStats();
            } else if (tabName === 'logs') {
                updateLogDisplay();
            }
        }

        function addExcludedDir() {
            const input = document.getElementById('exclude-dir');
            const dirName = input.value.trim();
            
            if (dirName && !excludedDirs.includes(dirName)) {
                excludedDirs.push(dirName);
                input.value = '';
                updateExcludedDirsDisplay();
            }
        }

        function removeExcludedDir(dirName) {
            excludedDirs = excludedDirs.filter(d => d !== dirName);
            updateExcludedDirsDisplay();
        }

        function updateExcludedDirsDisplay() {
            const container = document.getElementById('excluded-dirs');
            container.innerHTML = excludedDirs.map(dir => 
                `<span class="excluded-tag">${dir}<span class="remove" onclick="removeExcludedDir('${dir}')">&times;</span></span>`
            ).join('');
        }

        function startScan() {
            const scanPath = document.getElementById('scan-path').value;
            const dbPath = document.getElementById('db-path').value;
            const includeHidden = document.getElementById('include-hidden').checked;

            if (!scanPath) {
                showToast('Please enter a directory path to scan', 'error');
                return;
            }

            const data = {
                scan_path: scanPath,
                db_path: dbPath,
                include_hidden: includeHidden,
                excluded_dirs: excludedDirs
            };

            fetch('/api/start_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    currentScanId = result.scan_id;
                    document.getElementById('start-scan').disabled = true;
                    document.getElementById('stop-scan').disabled = false;
                    startScanStatusUpdates();
                } else {
                    showToast('Error: ' + result.error, 'error');
                }
            })
            .catch(error => {
                showToast('Error starting scan: ' + error, 'error');
            });
        }

        function stopScan() {
            if (scanStatusInterval) {
                clearInterval(scanStatusInterval);
            }
            document.getElementById('start-scan').disabled = false;
            document.getElementById('stop-scan').disabled = true;
            document.getElementById('scan-status').textContent = 'Scan stopped';
        }

        function startScanStatusUpdates() {
            scanStatusInterval = setInterval(updateScanStatus, 1000);
        }

        function updateScanStatus() {
            fetch('/api/scan_status')
            .then(response => response.json())
            .then(status => {
                document.getElementById('scan-status').textContent = status.progress;
                currentDirectory = status.current_directory;
                
                if (currentDirectory) {
                    document.getElementById('directory-filter').placeholder = `Current scan: ${currentDirectory}`;
                }
                
                updateLogDisplay(status.output);

                if (!status.running && scanStatusInterval) {
                    clearInterval(scanStatusInterval);
                    document.getElementById('start-scan').disabled = false;
                    document.getElementById('stop-scan').disabled = true;
                    
                    setTimeout(loadDuplicates, 1000);
                }
            })
            .catch(error => {
                console.error('Error updating scan status:', error);
            });
        }

        function updateLogDisplay(logs = []) {
            const logDisplay = document.getElementById('log-display');
            if (logs.length > 0) {
                logDisplay.innerHTML = logs.slice(-50).map(line => {
                    const className = line.toLowerCase().includes('error') ? 'log-entry error' : 'log-entry';
                    return `<div class="${className}">${line}</div>`;
                }).join('');
                logDisplay.scrollTop = logDisplay.scrollHeight;
            }
        }

        function loadStats() {
            const dbPath = document.getElementById('db-path').value;
            
            fetch(`/api/get_stats?db_path=${encodeURIComponent(dbPath)}`)
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    const stats = result.stats;
                    document.getElementById('stat-total-files').textContent = stats.total_files.toLocaleString();
                    document.getElementById('stat-unique-files').textContent = stats.unique_files.toLocaleString();
                    document.getElementById('stat-duplicate-files').textContent = stats.duplicate_files.toLocaleString();
                    document.getElementById('stat-ignored-sets').textContent = stats.ignored_sets.toLocaleString();
                    document.getElementById('stat-efficiency').textContent = stats.storage_efficiency + '%';
                    document.getElementById('stat-db-size').textContent = stats.database_size_mb + ' MB';
                } else {
                    showToast('Error loading statistics: ' + result.error, 'error');
                }
            })
            .catch(error => {
                showToast('Error loading statistics: ' + error, 'error');
            });
        }

        function loadDuplicates() {
            const dbPath = document.getElementById('db-path').value;
            const directoryFilter = document.getElementById('directory-filter').value || currentDirectory || '';
            const includeIgnored = document.getElementById('include-ignored').checked;
            
            const params = new URLSearchParams({
                db_path: dbPath,
                directory_filter: directoryFilter,
                include_ignored: includeIgnored
            });
            
            fetch(`/api/load_duplicates?${params}`)
            .then(response => response.json())
            .then(result => {
                if (result.error) {
                    showToast('Error: ' + result.error, 'error');
                    return;
                }

                const filterText = result.summary.directory_filter ? 
                    ` (filtered by: ${result.summary.directory_filter})` : 
                    ' (showing all directories)';
                const ignoredText = result.summary.include_ignored ? 
                    ' (including ignored)' : 
                    ' (excluding ignored)';

                document.getElementById('duplicates-info').textContent = 
                    `${result.summary.duplicate_sets} duplicate sets found (${result.summary.total_files} total files)${filterText}${ignoredText}`;

                displayDuplicates(result.duplicates);
            })
            .catch(error => {
                showToast('Error loading duplicates: ' + error, 'error');
            });
        }

        function refreshDuplicates() {
            loadDuplicates();
        }

        function toggleDuplicateSet(setId) {
            const header = document.getElementById(`header-${setId}`);
            const content = document.getElementById(`content-${setId}`);
            
            header.classList.toggle('collapsed');
            content.classList.toggle('collapsed');
        }

        function expandAllSets() {
            document.querySelectorAll('.duplicate-header').forEach(header => {
                header.classList.remove('collapsed');
            });
            document.querySelectorAll('.duplicate-content').forEach(content => {
                content.classList.remove('collapsed');
            });
        }

        function collapseAllSets() {
            document.querySelectorAll('.duplicate-header').forEach(header => {
                header.classList.add('collapsed');
            });
            document.querySelectorAll('.duplicate-content').forEach(content => {
                content.classList.add('collapsed');
            });
        }

        function ignoreDuplicateSet(sha1Hash, setId) {
            const dbPath = document.getElementById('db-path').value;
            const duplicateSetElement = document.querySelector(`#header-${setId}`).closest('.duplicate-set');
            
            duplicateSetElement.classList.add('fade-out');
            
            fetch('/api/ignore_duplicate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sha1_hash: sha1Hash, db_path: dbPath })
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    showToast('Duplicate set ignored', 'success');
                    setTimeout(() => {
                        duplicateSetElement.remove();
                        updateDuplicatesInfo();
                    }, 300);
                } else {
                    duplicateSetElement.classList.remove('fade-out');
                    showToast('Error: ' + result.error, 'error');
                }
            })
            .catch(error => {
                duplicateSetElement.classList.remove('fade-out');
                showToast('Error ignoring duplicate set: ' + error, 'error');
            });
        }

        function unignoreDuplicateSet(sha1Hash, setId) {
            const dbPath = document.getElementById('db-path').value;
            
            fetch('/api/unignore_duplicate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sha1_hash: sha1Hash, db_path: dbPath })
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    showToast('Duplicate set unignored', 'success');
                    refreshDuplicates();
                } else {
                    showToast('Error: ' + result.error, 'error');
                }
            })
            .catch(error => {
                showToast('Error unignoring duplicate set: ' + error, 'error');
            });
        }

        function updateDuplicatesInfo() {
            const remainingSets = document.querySelectorAll('.duplicate-set:not(.fade-out)').length;
            const currentInfo = document.getElementById('duplicates-info').textContent;
            const parts = currentInfo.split(' ');
            if (parts.length > 0) {
                parts[0] = remainingSets;
                document.getElementById('duplicates-info').textContent = parts.join(' ');
            }
        }

        function displayDuplicates(duplicates) {
            const container = document.getElementById('duplicates-container');
            
            if (duplicates.length === 0) {
                container.innerHTML = '<div class="card"><div style="text-align: center; color: var(--text-muted);">🎉 No duplicate files found.</div></div>';
                return;
            }

            container.innerHTML = duplicates.map((dupSet, setIndex) => `
                <div class="duplicate-set ${dupSet.ignored ? 'ignored' : ''}">
                    <div class="duplicate-header" id="header-${setIndex}" onclick="toggleDuplicateSet(${setIndex})">
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <div>
                                <strong>Duplicate Set #${setIndex + 1}</strong> 
                                (${dupSet.files.length} files) - Hash: ${dupSet.hash_short}
                            </div>
                            ${dupSet.ignored ? '<span class="status-badge status-warning">IGNORED</span>' : ''}
                        </div>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            ${dupSet.ignored ? 
                                `<button class="btn btn-secondary" style="font-size: 12px; padding: 4px 8px;" onclick="event.stopPropagation(); unignoreDuplicateSet('${dupSet.hash}', ${setIndex})">🔄 Unignore</button>` :
                                `<button class="btn btn-warning" style="font-size: 12px; padding: 4px 8px;" onclick="event.stopPropagation(); ignoreDuplicateSet('${dupSet.hash}', ${setIndex})">🙈 Ignore</button>`
                            }
                            <div class="toggle-icon">▼</div>
                        </div>
                    </div>
                    <div class="duplicate-content" id="content-${setIndex}">
                        ${dupSet.files.map(file => `
                            <div class="duplicate-file">
                                <div class="file-info">
                                    <div class="file-path">${file.path}</div>
                                    <div class="file-meta">
                                        <span>📏 Size: ${file.size}</span>
                                        <span>📅 Modified: ${file.modified}</span>
                                        <span style="color: ${file.exists ? 'var(--success-color)' : 'var(--danger-color)'}">
                                            ${file.exists ? '✓ Exists' : '✗ Missing'}
                                        </span>
                                    </div>
                                </div>
                                ${file.exists ? `
                                    <div class="btn-group">
                                        <button class="btn btn-secondary" style="font-size: 12px; padding: 6px 12px;" onclick="openFileLocation('${file.path.replace(/'/g, "\\'")}')">📂 Open Location</button>
                                        <button class="btn btn-danger" style="font-size: 12px; padding: 6px 12px;" onclick="deleteFile('${file.path.replace(/'/g, "\\'")}')">🗑️ Delete</button>
                                        <button class="btn btn-success" style="font-size: 12px; padding: 6px 12px;" onclick="keepOnlyFile('${file.path.replace(/'/g, "\\'")}', ${setIndex})">⭐ Keep Only This</button>
                                    </div>
                                ` : '<div style="color: var(--text-muted); font-style: italic;">File no longer exists</div>'}
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('');
        }

        function deleteFile(filePath) {
            if (!confirm(`Are you sure you want to delete this file?\\n\\n${filePath}`)) {
                return;
            }

            fetch('/api/delete_file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ file_path: filePath })
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    showToast('File deleted successfully', 'success');
                    refreshDuplicates();
                } else {
                    showToast('Error: ' + result.error, 'error');
                }
            })
            .catch(error => {
                showToast('Error deleting file: ' + error, 'error');
            });
        }

        function openFileLocation(filePath) {
            fetch('/api/open_file_location', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ file_path: filePath })
            })
            .then(response => response.json())
            .then(result => {
                if (!result.success) {
                    showToast('Error: ' + result.error, 'error');
                }
            })
            .catch(error => {
                showToast('Error opening file location: ' + error, 'error');
            });
        }

        function keepOnlyFile(filePath, duplicateSetId) {
            if (!confirm(`Keep this file and delete all others in this duplicate set?\\n\\n${filePath}`)) {
                return;
            }

            fetch('/api/keep_only_file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    file_path: filePath, 
                    duplicate_set_id: duplicateSetId 
                })
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    let message = `Successfully deleted ${result.deleted_count} files.`;
                    if (result.errors.length > 0) {
                        message = `Deleted ${result.deleted_count} files with ${result.errors.length} errors.`;
                        showToast(message, 'error');
                    } else {
                        showToast(message, 'success');
                    }
                    refreshDuplicates();
                } else {
                    showToast('Error: ' + result.error, 'error');
                }
            })
            .catch(error => {
                showToast('Error: ' + error, 'error');
            });
        }

        // Event listeners
        document.getElementById('exclude-dir').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                addExcludedDir();
            }
        });

        document.getElementById('directory-filter').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                loadDuplicates();
            }
        });

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            const scanPathInput = document.getElementById('scan-path');
            const userAgent = navigator.userAgent;
            if (userAgent.includes('Windows')) {
                scanPathInput.placeholder = 'e.g., C:\\\\Users\\\\YourName\\\\Documents';
            } else if (userAgent.includes('Mac')) {
                scanPathInput.placeholder = 'e.g., /Users/YourName/Documents';
            } else {
                scanPathInput.placeholder = 'e.g., /home/username/Documents';
            }
        });
    </script>
</body>
</html>'''

    with open(os.path.join(templates_dir, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(html_content)
