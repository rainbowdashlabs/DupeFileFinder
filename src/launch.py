#!/usr/bin/env python3
"""
Launcher for the Web-based File Scanner GUI.
"""

import sys
import os

# Add current directory to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from web_scanner_gui import app, create_html_template
    
    # Create HTML template
    create_html_template()
    
    print("=" * 50)
    print("File Duplicate Scanner Web GUI")
    print("=" * 50)
    print("Starting web server...")
    print("Open your browser and go to: http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    print("=" * 50)
    
    app.run(debug=False, host='localhost', port=5000)
    
except ImportError as e:
    print(f"Error importing Web GUI: {e}")
    print("Make sure file_duplicate_scanner.py is in the same directory.")
    print("Also install Flask: pipenv install flask")
    sys.exit(1)
except Exception as e:
    print(f"Error running Web GUI: {e}")
    sys.exit(1)
