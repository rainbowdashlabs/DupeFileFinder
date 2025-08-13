
#!/usr/bin/env python3
"""
File duplicate scanner that processes files in a directory,
stores metadata in SQLite, and identifies duplicates.
Updated to only scan files that are missing or have changed modification times.
Uses absolute paths to prevent rescanning known files.
Excludes hidden directories and files by default with opt-in option to include them.
Supports excluding specific directories via --exclude-directory parameter.
"""

import argparse
import os
import sqlite3
import hashlib
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Set
from dataclasses import dataclass


@dataclass
class ScanStats:
    """Statistics tracking for file scanning operations."""
    files_processed: int = 0
    files_skipped: int = 0
    files_updated: int = 0
    files_added: int = 0
    dirs_skipped: int = 0
    hidden_files_skipped: int = 0
    removed_count: int = 0


def create_database(db_path: str) -> sqlite3.Connection:
    """Create SQLite database and table for file metadata."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL UNIQUE,
            sha1_hash TEXT NOT NULL,
            modified_time TIMESTAMP NOT NULL,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create table for ignored duplicate sets
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ignored_duplicates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sha1_hash TEXT NOT NULL UNIQUE,
            ignored_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create indexes for faster lookups
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_sha1_hash ON files(sha1_hash)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_file_path ON files(file_path)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_ignored_hash ON ignored_duplicates(sha1_hash)
    ''')
    
    conn.commit()
    return conn


def calculate_sha1(file_path: str) -> str:
    """Calculate SHA1 hash of a file."""
    sha1_hash = hashlib.sha1()
    try:
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b""):
                sha1_hash.update(chunk)
        return sha1_hash.hexdigest()
    except (IOError, OSError) as e:
        print(f"Error reading file {file_path}: {e}")
        return ""


def get_file_modified_time(file_path: str) -> datetime:
    """Get the modification time of a file."""
    try:
        timestamp = os.path.getmtime(file_path)
        return datetime.fromtimestamp(timestamp)
    except (IOError, OSError) as e:
        print(f"Error getting modification time for {file_path}: {e}")
        return datetime.now()


def normalize_path(file_path: str) -> str:
    """
    Convert file path to absolute, normalized path.
    This ensures consistent path storage regardless of how the scanner is invoked.
    """
    return os.path.abspath(os.path.normpath(file_path))


def is_hidden(path: str) -> bool:
    """
    Check if a file or directory is hidden (starts with a dot).
    Returns True if the file/directory name starts with a dot.
    """
    name = os.path.basename(path)
    return name.startswith('.') and name not in ['.', '..']


def should_skip_directory(dir_path: str, include_hidden: bool, excluded_dirs: Set[str]) -> bool:
    """
    Determine if a directory should be skipped during scanning.
    
    Args:
        dir_path: Path to the directory
        include_hidden: Whether to include hidden directories
        excluded_dirs: Set of directory names/paths to exclude
        
    Returns:
        True if directory should be skipped, False otherwise
    """
    # Check if it's a hidden directory
    if not include_hidden and is_hidden(dir_path):
        return True
    
    # Check if it's in the excluded directories list
    dir_name = os.path.basename(dir_path)
    abs_dir_path = normalize_path(dir_path)
    
    # Check against excluded directories (support both names and absolute paths)
    for excluded in excluded_dirs:
        if excluded == dir_name or normalize_path(excluded) == abs_dir_path:
            return True
    
    return False


def should_skip_file(file_path: str, include_hidden: bool) -> bool:
    """
    Determine if a file should be skipped during scanning.
    
    Args:
        file_path: Path to the file
        include_hidden: Whether to include hidden files
        
    Returns:
        True if file should be skipped, False otherwise
    """
    # Check if it's a hidden file
    if not include_hidden and is_hidden(file_path):
        return True
    
    return False


def get_existing_files_info(conn: sqlite3.Connection) -> dict:
    """
    Get information about files already in the database.
    Returns dict: {absolute_file_path: modified_time}
    """
    cursor = conn.cursor()
    cursor.execute('SELECT file_path, modified_time FROM files')
    
    existing_files = {}
    for file_path, modified_time_str in cursor.fetchall():
        # Convert string back to datetime for comparison
        try:
            modified_time = datetime.fromisoformat(modified_time_str.replace('Z', '+00:00')) if 'Z' in modified_time_str else datetime.fromisoformat(modified_time_str)
        except ValueError:
            # Handle different datetime formats
            try:
                modified_time = datetime.strptime(modified_time_str, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                modified_time = datetime.strptime(modified_time_str, '%Y-%m-%d %H:%M:%S')
        
        existing_files[file_path] = modified_time
    
    return existing_files


def remove_deleted_files(conn: sqlite3.Connection, scanned_paths: Set[str]) -> int:
    """
    Remove files from database that no longer exist on disk.
    Returns number of files removed.
    """
    cursor = conn.cursor()
    cursor.execute('SELECT file_path FROM files')
    db_files = {row[0] for row in cursor.fetchall()}
    
    # Find files in database that weren't found during scan
    deleted_files = db_files - scanned_paths
    
    removed_count = 0
    for file_path in deleted_files:
        if not os.path.exists(file_path):  # Double-check file doesn't exist
            cursor.execute('DELETE FROM files WHERE file_path = ?', (file_path,))
            removed_count += 1
            print(f"Removed deleted file from database: {file_path}")
    
    if removed_count > 0:
        conn.commit()
        print(f"Removed {removed_count} deleted files from database.")
    
    return removed_count


def validate_scan_path(directory_path: str) -> str:
    """
    Validate and normalize the scan path.
    
    Args:
        directory_path: Path to validate
        
    Returns:
        Absolute normalized path
        
    Raises:
        ValueError: If path doesn't exist or is not a directory
    """
    abs_directory_path = normalize_path(directory_path)
    path = Path(abs_directory_path)
    
    if not path.exists():
        raise ValueError(f"Path '{directory_path}' does not exist.")
    
    if not path.is_dir():
        raise ValueError(f"'{directory_path}' is not a directory.")
    
    return abs_directory_path


def print_scan_header(abs_directory_path: str, include_hidden: bool, excluded_dirs: List[str]):
    """Print header information for the scan."""
    print(f"Scanning files in: {abs_directory_path}")
    if include_hidden:
        print("Including hidden files and directories (starting with '.')")
    else:
        print("Excluding hidden files and directories (use --include-hidden to include them)")
    
    if excluded_dirs:
        print(f"Excluding directories: {', '.join(excluded_dirs)}")


def filter_directories(dirs: List[str], root: str, include_hidden: bool, excluded_dirs_set: Set[str], stats: ScanStats) -> None:
    """
    Filter directories list in-place to exclude unwanted directories.
    
    Args:
        dirs: List of directory names to filter (modified in-place)
        root: Current root directory path
        include_hidden: Whether to include hidden directories
        excluded_dirs_set: Set of directories to exclude
        stats: Statistics object to update
    """
    dirs_to_remove = []
    for dir_name in dirs:
        dir_path = os.path.join(root, dir_name)
        if should_skip_directory(dir_path, include_hidden, excluded_dirs_set):
            dirs_to_remove.append(dir_name)
            stats.dirs_skipped += 1
            if stats.dirs_skipped <= 10:  # Show first 10 skipped directories
                if is_hidden(dir_path):
                    print(f"Skipping hidden directory: {dir_path}")
                else:
                    print(f"Skipping excluded directory: {dir_path}")
            elif stats.dirs_skipped == 11:
                print("... (additional directories skipped)")
    
    # Remove skipped directories from the dirs list to prevent os.walk from descending into them
    for dir_name in dirs_to_remove:
        dirs.remove(dir_name)


def check_file_needs_processing(abs_file_path: str, existing_files: dict, current_modified_time: datetime) -> Tuple[bool, bool]:
    """
    Check if a file needs processing based on its existence and modification time.
    
    Args:
        abs_file_path: Absolute path to the file
        existing_files: Dictionary of existing files and their modification times
        current_modified_time: Current modification time of the file
        
    Returns:
        Tuple of (needs_processing, is_new_file)
    """
    is_new_file = abs_file_path not in existing_files
    
    if is_new_file:
        print(f"New file: {abs_file_path}")
        return True, True
    else:
        # Compare modification times
        db_modified_time = existing_files[abs_file_path]
        # Allow for small time differences due to precision
        time_diff = abs((current_modified_time - db_modified_time).total_seconds())
        if time_diff > 1:  # More than 1 second difference
            print(f"Modified file: {abs_file_path} (time diff: {time_diff:.2f}s)")
            return True, False
        else:
            return False, False


def process_file_to_database(abs_file_path: str, sha1_hash: str, current_modified_time: datetime, 
                           is_new_file: bool, cursor: sqlite3.Cursor) -> None:
    """
    Insert or update file information in the database.
    
    Args:
        abs_file_path: Absolute path to the file
        sha1_hash: SHA1 hash of the file
        current_modified_time: Current modification time
        is_new_file: Whether this is a new file or an update
        cursor: Database cursor
    """
    if is_new_file:
        # Insert new file with absolute path
        cursor.execute('''
            INSERT INTO files (file_path, sha1_hash, modified_time)
            VALUES (?, ?, ?)
        ''', (abs_file_path, sha1_hash, current_modified_time))
    else:
        # Update existing file
        cursor.execute('''
            UPDATE files 
            SET sha1_hash = ?, modified_time = ?, scan_time = CURRENT_TIMESTAMP
            WHERE file_path = ?
        ''', (sha1_hash, current_modified_time, abs_file_path))


def process_single_file(file_path: str, root: str, include_hidden: bool, existing_files: dict,
                       cursor: sqlite3.Cursor, conn: sqlite3.Connection, stats: ScanStats,
                       scanned_paths: Set[str]) -> None:
    """
    Process a single file during directory scanning.
    
    Args:
        file_path: Relative file path
        root: Current directory root
        include_hidden: Whether to include hidden files
        existing_files: Dictionary of existing files from database
        cursor: Database cursor
        conn: Database connection
        stats: Statistics object to update
        scanned_paths: Set to track scanned paths
    """
    # Create absolute path immediately
    relative_file_path = os.path.join(root, file_path)
    abs_file_path = normalize_path(relative_file_path)
    
    try:
        # Skip if it's not a regular file
        if not os.path.isfile(abs_file_path):
            return
        
        # Check if file should be skipped
        if should_skip_file(abs_file_path, include_hidden):
            stats.hidden_files_skipped += 1
            if stats.hidden_files_skipped <= 5:  # Show first few skipped files
                print(f"Skipping hidden file: {abs_file_path}")
            elif stats.hidden_files_skipped == 6:
                print("... (additional hidden files skipped)")
            return
        
        scanned_paths.add(abs_file_path)
        
        # Get current modification time
        current_modified_time = get_file_modified_time(abs_file_path)
        
        # Check if file needs to be processed
        needs_processing, is_new_file = check_file_needs_processing(
            abs_file_path, existing_files, current_modified_time
        )
        
        if not needs_processing:
            stats.files_skipped += 1
            if stats.files_skipped % 100 == 0:  # Progress indicator for skipped files
                print(f"Skipped {stats.files_skipped} unchanged files...")
            return
        
        print(f"Processing: {abs_file_path}")
        
        # Calculate SHA1 hash
        sha1_hash = calculate_sha1(abs_file_path)
        if not sha1_hash:  # Skip if hash calculation failed
            return
        
        # Process to database
        process_file_to_database(abs_file_path, sha1_hash, current_modified_time, is_new_file, cursor)
        
        if is_new_file:
            stats.files_added += 1
        else:
            stats.files_updated += 1
        
        stats.files_processed += 1
        
        # Commit periodically for large scans
        if stats.files_processed % 100 == 0:
            conn.commit()
            print(f"Processed {stats.files_processed} files so far...")
    
    except Exception as e:
        print(f"Error processing file {abs_file_path}: {e}")


def print_scan_results(stats: ScanStats) -> None:
    """Print the results of the scan operation."""
    print(f"\nScan completed:")
    print(f"  Files added: {stats.files_added}")
    print(f"  Files updated: {stats.files_updated}")
    print(f"  Files removed: {stats.removed_count}")
    print(f"  Files skipped (unchanged): {stats.files_skipped}")
    print(f"  Hidden files skipped: {stats.hidden_files_skipped}")
    print(f"  Directories skipped: {stats.dirs_skipped}")
    print(f"  Total files processed: {stats.files_processed}")


def scan_files(directory_path: str, conn: sqlite3.Connection, include_hidden: bool = False, excluded_dirs: List[str] = None) -> int:
    """
    Scan files in the given directory and update database incrementally.
    Only processes files that are missing or have changed modification times.
    Uses absolute paths to ensure consistent file identification.
    
    Args:
        directory_path: Path to scan
        conn: Database connection
        include_hidden: Whether to include hidden files and directories (starting with dot)
        excluded_dirs: List of directory names/paths to exclude
        
    Returns:
        Number of files processed.
    """
    if excluded_dirs is None:
        excluded_dirs = []
    
    excluded_dirs_set = set(excluded_dirs)
    cursor = conn.cursor()
    stats = ScanStats()
    
    try:
        # Validate and normalize the path
        abs_directory_path = validate_scan_path(directory_path)
        
        # Print scan information
        print_scan_header(abs_directory_path, include_hidden, excluded_dirs)
        
        # Get existing files info from database
        existing_files = get_existing_files_info(conn)
        print(f"Found {len(existing_files)} files in database.")
        
        # Keep track of all absolute file paths we encounter
        scanned_paths = set()
        
        # Walk through all files in the directory tree
        for root, dirs, files in os.walk(abs_directory_path):
            # Filter out directories that should be skipped
            filter_directories(dirs, root, include_hidden, excluded_dirs_set, stats)
            
            # Process files in current directory
            for file in files:
                process_single_file(file, root, include_hidden, existing_files,
                                  cursor, conn, stats, scanned_paths)
        
        # Final commit
        conn.commit()
        
        # Remove deleted files from database (only those that were in scan scope)
        if scanned_paths:  # Only if we actually scanned some files
            stats.removed_count = remove_deleted_files(conn, scanned_paths)
        
        # Print results
        print_scan_results(stats)
        
    except ValueError as e:
        print(f"Error: {e}")
        return 0
    except Exception as e:
        print(f"Error scanning directory: {e}")
        return 0
    
    return stats.files_processed


def find_duplicates(conn: sqlite3.Connection, directory_filter: str = None, include_ignored: bool = False) -> List[Tuple[str, List[str]]]:
    """
    Find duplicate files based on SHA1 hash.
    
    Args:
        conn: Database connection
        directory_filter: Only return duplicates within this directory
        include_ignored: Whether to include ignored duplicate sets
    
    Returns:
        List of tuples: (hash, [list of file paths with that hash])
    """
    cursor = conn.cursor()
    
    # Base query to find SHA1 hashes that appear more than once
    base_query = '''
        SELECT sha1_hash, COUNT(*) as count
        FROM files
    '''
    
    params = []
    where_conditions = []
    
    # Filter by directory if specified
    if directory_filter:
        normalized_dir = normalize_path(directory_filter)
        where_conditions.append("file_path LIKE ?")
        params.append(f"{normalized_dir}%")
    
    # Filter out ignored duplicates unless explicitly requested
    if not include_ignored:
        where_conditions.append('''
            sha1_hash NOT IN (SELECT sha1_hash FROM ignored_duplicates)
        ''')
    
    # Add WHERE clause if we have conditions
    if where_conditions:
        base_query += " WHERE " + " AND ".join(where_conditions)
    
    base_query += '''
        GROUP BY sha1_hash
        HAVING count > 1
        ORDER BY count DESC
    '''
    
    cursor.execute(base_query, params)
    duplicate_hashes = cursor.fetchall()
    duplicates = []
    
    for sha1_hash, count in duplicate_hashes:
        # Get all file paths for this hash
        file_query = '''
            SELECT file_path, modified_time
            FROM files
            WHERE sha1_hash = ?
        '''
        file_params = [sha1_hash]
        
        # Apply directory filter to individual files as well
        if directory_filter:
            normalized_dir = normalize_path(directory_filter)
            file_query += " AND file_path LIKE ?"
            file_params.append(f"{normalized_dir}%")
        
        file_query += " ORDER BY modified_time"
        
        cursor.execute(file_query, file_params)
        file_paths = [row[0] for row in cursor.fetchall()]
        
        # Only include if we still have duplicates after filtering
        if len(file_paths) > 1:
            duplicates.append((sha1_hash, file_paths))
    
    return duplicates


def ignore_duplicate_set(conn: sqlite3.Connection, sha1_hash: str) -> bool:
    """
    Mark a duplicate set as ignored.
    
    Args:
        conn: Database connection
        sha1_hash: Hash of the duplicate set to ignore
        
    Returns:
        True if successful, False otherwise
    """
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO ignored_duplicates (sha1_hash)
            VALUES (?)
        ''', (sha1_hash,))
        conn.commit()
        return True
    except Exception:
        return False


def unignore_duplicate_set(conn: sqlite3.Connection, sha1_hash: str) -> bool:
    """
    Remove a duplicate set from the ignored list.
    
    Args:
        conn: Database connection
        sha1_hash: Hash of the duplicate set to unignore
        
    Returns:
        True if successful, False otherwise
    """
    try:
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM ignored_duplicates
            WHERE sha1_hash = ?
        ''', (sha1_hash,))
        conn.commit()
        return True
    except Exception:
        return False


def print_duplicates(duplicates: List[Tuple[str, List[str]]]) -> None:
    """Print duplicate files in a readable format."""
    if not duplicates:
        print("\nNo duplicate files found.")
        return
    
    print(f"\nFound {len(duplicates)} sets of duplicate files:")
    print("=" * 60)
    
    for i, (sha1_hash, file_paths) in enumerate(duplicates, 1):
        print(f"\nDuplicate Set #{i} (SHA1: {sha1_hash[:16]}...):")
        print(f"  {len(file_paths)} identical files:")
        for file_path in file_paths:
            print(f"    - {file_path}")


def print_database_stats(conn: sqlite3.Connection) -> None:
    """Print statistics about the database."""
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
    
    print(f"\nDatabase Statistics:")
    print(f"  Total files: {total_files}")
    print(f"  Unique files: {unique_hashes}")
    print(f"  Duplicate files: {duplicate_files}")
    print(f"  Ignored duplicate sets: {ignored_sets}")
    print(f"  Storage efficiency: {((unique_hashes/total_files)*100):.1f}%" if total_files > 0 else "  Storage efficiency: N/A")


def main():
    """Main function to handle command line arguments and orchestrate the process."""
    parser = argparse.ArgumentParser(
        description="Incrementally scan files in a directory, store metadata in SQLite, and find duplicates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /home/user/documents
  %(prog)s . --include-hidden --verbose
  %(prog)s /path/to/scan --exclude-directory node_modules --exclude-directory .git
  %(prog)s ~/Downloads --exclude-directory temp --exclude-directory cache -v
  %(prog)s /media/backup --include-hidden --exclude-directory lost+found
        """
    )
    parser.add_argument(
        "path",
        help="Directory path to scan for files (will be converted to absolute path)"
    )
    parser.add_argument(
        "--db",
        default="file_scanner.db",
        help="SQLite database file path (default: file_scanner.db)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show database statistics"
    )
    parser.add_argument(
        "--include-hidden",
        action="store_true",
        help="Include hidden files and directories (starting with '.') in the scan. "
             "By default, hidden files and directories like .git, .cache, .bashrc etc. are excluded."
    )
    parser.add_argument(
        "--exclude-directory",
        action="append",
        dest="excluded_dirs",
        metavar="DIR",
        help="Exclude a specific directory from scanning. Can be specified multiple times. "
             "Accepts either directory names (e.g., 'node_modules') or absolute paths. "
             "Directory names will match any directory with that name in the scan tree."
    )
    
    args = parser.parse_args()
    
    # Ensure excluded_dirs is always a list
    if args.excluded_dirs is None:
        args.excluded_dirs = []
    
    try:
        # Create database connection
        conn = create_database(args.db)
        
        # Scan files and store in database (incremental)
        files_processed = scan_files(
            args.path, 
            conn, 
            include_hidden=args.include_hidden, 
            excluded_dirs=args.excluded_dirs
        )
        
        # Show database statistics if requested
        if args.stats:
            print_database_stats(conn)
        
        # Find and display duplicates (filtered to scanned directory)
        duplicates = find_duplicates(conn, directory_filter=args.path)
        print_duplicates(duplicates)
        
        # Print summary
        abs_path = normalize_path(args.path)
        print(f"\nScan Summary:")
        print(f"  Directory: {abs_path}")
        print(f"  Hidden files/directories: {'Included' if args.include_hidden else 'Excluded'}")
        if args.excluded_dirs:
            print(f"  Excluded directories: {', '.join(args.excluded_dirs)}")
        print(f"  Files processed this scan: {files_processed}")
        print(f"  Duplicate sets found: {len(duplicates)}")
        print(f"  Database: {os.path.abspath(args.db)}")
        
        # Return list of all duplicate file paths
        all_duplicate_paths = []
        for _, file_paths in duplicates:
            all_duplicate_paths.extend(file_paths)
        
        if args.verbose and all_duplicate_paths:
            print(f"\nAll duplicate file paths ({len(all_duplicate_paths)} files):")
            for path in sorted(all_duplicate_paths):
                print(f"  {path}")
        
        conn.close()
        return 0
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
