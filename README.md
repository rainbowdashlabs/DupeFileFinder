# File Duplicate Scanner

⚠️ **AI-Generated Code - Use at Your Own Risk** ⚠️

![Unbenannt](https://github.com/user-attachments/assets/7f4cd695-60e2-4043-b364-397b02ce9af7)

**This project was generated using AI assistance. While efforts have been made to ensure functionality and safety, this code has not been extensively tested in all environments. Use this software at your own risk and always backup your important data before running any file deletion operations.**

## Overview

A powerful Python-based tool for finding and managing duplicate files on your system. The scanner uses SHA1 hashing to identify identical files and provides both command-line and web-based interfaces for managing duplicates.

### Key Features

- 🔍 **Incremental Scanning**: Only processes new or modified files for efficiency
- 🌐 **Web-based GUI**: Modern, responsive interface for easy duplicate management
- 💾 **SQLite Database**: Persistent storage of file metadata and scan results
- 🚫 **Smart Filtering**: Exclude hidden files and specific directories
- 📂 **Directory-specific Results**: Filter duplicates by directory
- 🙈 **Ignore Functionality**: Mark duplicate sets as ignored to hide them
- ⚡ **Performance Optimized**: Uses absolute paths and incremental updates
- 🗑️ **Safe File Management**: Delete individual files or keep only one from a set

## ⚠️ Important Safety Notice

**BACKUP YOUR DATA**: This tool can delete files permanently. Always ensure you have proper backups before using the deletion features.

**TEST FIRST**: Try the tool on a small test directory before using it on important data.

**REVIEW BEFORE DELETING**: Carefully review duplicate files before deletion to avoid losing important data.

## Installation

### Prerequisites

- Python 3.13+ (tested with Python 3.13.0)
- pipenv (for dependency management)

### Setup

1. **Clone or download the project files**
2. **Install dependencies**:
   ```bash
   pipenv sync
   ```
3. **Activate the virtual environment**:
   ```bash
   pipenv shell
   ```

## Usage

### Web Interface (Recommended)

The web interface provides the easiest way to use the scanner:

```bash
python ./src/launcher.py
```

Then open your browser to: `http://localhost:5000`
#### Web Interface Features:
1. **Scan Configuration Tab**:
    - Select directory to scan
    - Configure database location
    - Toggle hidden file inclusion
    - Add excluded directories
    - Monitor scan progress in real-time

2. **Manage Duplicates Tab**:
    - View duplicate sets with collapsible sections
    - Filter by directory
    - Toggle display of ignored sets
    - Delete individual files
    - Keep only one file from a duplicate set
    - Mark entire duplicate sets as ignored
    - Open file locations in system file manager

### Command Line Interface
For advanced users and automation:
#### Basic Usage
``` bash
# Scan current directory
python file_duplicate_scanner.py .

# Scan specific directory
python file_duplicate_scanner.py /path/to/scan

# Scan with custom database
python file_duplicate_scanner.py /path/to/scan --db my_scan.db
```
#### Advanced Options
``` bash
# Include hidden files and directories
python file_duplicate_scanner.py /path/to/scan --include-hidden

# Exclude specific directories
python file_duplicate_scanner.py /path/to/scan --exclude-directory node_modules --exclude-directory .git

# Show database statistics
python file_duplicate_scanner.py /path/to/scan --stats

# Verbose output
python file_duplicate_scanner.py /path/to/scan --verbose
```
#### Command Line Arguments

| Argument | Description |
| --- | --- |
| `path` | Directory path to scan (required) |
| `--db` | SQLite database file path (default: file_scanner.db) |
| `--include-hidden` | Include hidden files and directories |
| `--exclude-directory DIR` | Exclude specific directory (can be used multiple times) |
| `--verbose, -v` | Enable verbose output |
| `--stats` | Show database statistics |
### Example Workflows
#### 1. First-time Scan
``` bash
# Start with web interface
python run_web_gui.py

# Or command line
python file_duplicate_scanner.py ~/Documents --exclude-directory .git
```
#### 2. Regular Maintenance
``` bash
# Rescan same directory (only processes changed files)
python file_duplicate_scanner.py ~/Documents
```
#### 3. Comprehensive Scan
``` bash
# Scan including hidden files, excluding temporary directories
python file_duplicate_scanner.py / --include-hidden --exclude-directory tmp --exclude-directory cache --exclude-directory .cache
```
## How It Works
### Scanning Process
1. **Directory Traversal**: Recursively walks through the specified directory
2. **File Filtering**: Excludes hidden files and specified directories by default
3. **Incremental Processing**: Only processes files that are new or have changed modification times
4. **SHA1 Hashing**: Calculates SHA1 hash for each processed file
5. **Database Storage**: Stores file metadata (path, hash, modification time) in SQLite
6. **Duplicate Detection**: Identifies files with identical SHA1 hashes

### Database Schema
The tool creates a SQLite database with two main tables:
- **files**: Stores file metadata (path, hash, modification time)
- : Tracks duplicate sets marked as ignored **ignored_duplicates**

### Performance Features
- **Absolute Path Storage**: Prevents rescanning when working directory changes
- **Incremental Updates**: Only processes new or modified files on subsequent scans
- **Indexed Database**: Uses database indexes for fast duplicate lookups
- **Chunked File Reading**: Handles large files efficiently
- **Progress Indicators**: Shows scan progress for long operations

## File Structure
``` 
├── file_duplicate_scanner.py    # Core scanner logic (command line)
├── web_scanner_gui.py          # Web interface backend (Flask)
├── run_web_gui.py             # Web interface launcher
├── templates/
│   └── index.html             # Web interface frontend
├── Pipfile                    # Python dependencies
└── README.md                  # This file
```
## Dependencies
- **Flask**: Web interface framework
- **Standard Library**: sqlite3, hashlib, pathlib, argparse, os, sys, datetime

No external dependencies required for core functionality (command line interface).
## Troubleshooting
Its ai made, so ask an ai...
