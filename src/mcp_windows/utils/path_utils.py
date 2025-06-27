"""
Path manipulation utilities for MCP Windows Development Server.

This module provides helper functions for Windows path operations including
junction points, symbolic links, path normalization, and safe path handling.
"""

import os
import shutil
import tempfile
import hashlib
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import ctypes
from ctypes import wintypes
import contextlib

import win32api
import win32con
import win32file
import pywintypes
import structlog

logger = structlog.get_logger(__name__)


# Windows constants for reparse points
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_SYMLINK = 0xA000000C
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000


class PathUtils:
    """Utility class for Windows path operations."""
    
    # Common Windows reserved names
    RESERVED_NAMES = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    }
    
    # Invalid filename characters on Windows
    INVALID_CHARS = '<>:"|?*'
    
    @staticmethod
    def normalize_path(path: Union[str, Path]) -> Path:
        """
        Normalize a Windows path.
        
        Args:
            path: Path to normalize
            
        Returns:
            Normalized Path object
        """
        # Convert to Path object
        path = Path(path) if isinstance(path, str) else path
        
        # Resolve to absolute path
        try:
            path = path.resolve()
        except Exception:
            # If resolve fails, use absolute
            path = path.absolute()
        
        # Handle UNC paths
        if str(path).startswith("\\\\"):
            return path
        
        # Ensure drive letter is uppercase
        parts = path.parts
        if parts and len(parts[0]) == 3 and parts[0][1] == ":":
            drive = parts[0].upper()
            path = Path(drive).joinpath(*parts[1:])
        
        return path
    
    @staticmethod
    def is_safe_filename(filename: str) -> Tuple[bool, Optional[str]]:
        """
        Check if filename is safe for Windows.
        
        Args:
            filename: Filename to check
            
        Returns:
            Tuple of (is_safe, reason_if_not)
        """
        # Check for empty
        if not filename or filename.isspace():
            return False, "Filename cannot be empty"
        
        # Check length
        if len(filename) > 255:
            return False, "Filename too long (max 255 characters)"
        
        # Check for invalid characters
        for char in PathUtils.INVALID_CHARS:
            if char in filename:
                return False, f"Invalid character '{char}' in filename"
        
        # Check for reserved names
        name_without_ext = filename.split('.')[0].upper()
        if name_without_ext in PathUtils.RESERVED_NAMES:
            return False, f"'{name_without_ext}' is a reserved filename"
        
        # Check for trailing dots or spaces
        if filename.endswith('.') or filename.endswith(' '):
            return False, "Filename cannot end with dot or space"
        
        # Check for control characters
        for char in filename:
            if ord(char) < 32:
                return False, "Filename contains control characters"
        
        return True, None
    
    @staticmethod
    def sanitize_filename(filename: str, replacement: str = "_") -> str:
        """
        Sanitize filename for Windows.
        
        Args:
            filename: Filename to sanitize
            replacement: Character to replace invalid chars with
            
        Returns:
            Sanitized filename
        """
        # Replace invalid characters
        for char in PathUtils.INVALID_CHARS:
            filename = filename.replace(char, replacement)
        
        # Handle reserved names
        name_parts = filename.split('.')
        if name_parts[0].upper() in PathUtils.RESERVED_NAMES:
            name_parts[0] = f"{replacement}{name_parts[0]}"
            filename = '.'.join(name_parts)
        
        # Remove control characters
        filename = ''.join(
            char if ord(char) >= 32 else replacement 
            for char in filename
        )
        
        # Trim trailing dots and spaces
        filename = filename.rstrip('. ')
        
        # Ensure not empty
        if not filename:
            filename = "unnamed"
        
        # Truncate if too long
        if len(filename) > 255:
            # Preserve extension if possible
            if '.' in filename:
                base, ext = filename.rsplit('.', 1)
                max_base = 255 - len(ext) - 1
                filename = f"{base[:max_base]}.{ext}"
            else:
                filename = filename[:255]
        
        return filename
    
    @staticmethod
    def create_junction(source: Path, target: Path) -> bool:
        """
        Create a Windows junction point.
        
        Args:
            source: Junction path to create
            target: Target directory path
            
        Returns:
            Success status
        """
        try:
            # Ensure target exists and is a directory
            if not target.exists():
                raise ValueError(f"Target does not exist: {target}")
            if not target.is_dir():
                raise ValueError(f"Target must be a directory: {target}")
            
            # Ensure source doesn't exist
            if source.exists():
                raise ValueError(f"Source already exists: {source}")
            
            # Create junction using mklink
            cmd = f'mklink /J "{source}" "{target}"'
            result = os.system(cmd)
            
            return result == 0 and source.exists()
            
        except Exception as e:
            logger.error(f"Failed to create junction {source} -> {target}: {e}")
            return False
    
    @staticmethod
    def create_symlink(source: Path, target: Path, is_dir: bool = None) -> bool:
        """
        Create a Windows symbolic link.
        
        Args:
            source: Symlink path to create
            target: Target path
            is_dir: Whether target is directory (auto-detected if None)
            
        Returns:
            Success status
        """
        try:
            # Auto-detect if target is directory
            if is_dir is None:
                is_dir = target.is_dir() if target.exists() else False
            
            # Create symlink
            source.symlink_to(target, target_is_directory=is_dir)
            return True
            
        except OSError as e:
            if e.winerror == 1314:  # Privilege not held
                logger.error(
                    "Creating symbolic links requires administrative privileges "
                    "or developer mode enabled"
                )
            else:
                logger.error(f"Failed to create symlink {source} -> {target}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to create symlink {source} -> {target}: {e}")
            return False
    
    @staticmethod
    def is_junction(path: Path) -> bool:
        """
        Check if path is a junction point.
        
        Args:
            path: Path to check
            
        Returns:
            True if junction point
        """
        try:
            if not path.exists():
                return False
            
            # Get file attributes
            attrs = win32file.GetFileAttributes(str(path))
            
            # Check for reparse point
            if not (attrs & win32con.FILE_ATTRIBUTE_REPARSE_POINT):
                return False
            
            # Get reparse tag
            handle = win32file.CreateFile(
                str(path),
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_OPEN_REPARSE_POINT | 
                win32con.FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
            
            try:
                info = win32file.DeviceIoControl(
                    handle,
                    win32file.FSCTL_GET_REPARSE_POINT,
                    None,
                    10240
                )
                
                # Check reparse tag
                tag = int.from_bytes(info[:4], 'little')
                return tag == IO_REPARSE_TAG_MOUNT_POINT
                
            finally:
                win32api.CloseHandle(handle)
                
        except Exception:
            return False
    
    @staticmethod
    def get_junction_target(path: Path) -> Optional[Path]:
        """
        Get target of a junction point.
        
        Args:
            path: Junction path
            
        Returns:
            Target path or None
        """
        if not PathUtils.is_junction(path):
            return None
        
        try:
            # Open junction
            handle = win32file.CreateFile(
                str(path),
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_OPEN_REPARSE_POINT |
                win32con.FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
            
            try:
                # Get reparse data
                data = win32file.DeviceIoControl(
                    handle,
                    win32file.FSCTL_GET_REPARSE_POINT,
                    None,
                    10240
                )
                
                # Parse reparse data buffer
                # Skip first 8 bytes (tag and length)
                # Next 4 shorts: substitute name offset/length, print name offset/length
                substitute_name_offset = int.from_bytes(data[8:10], 'little')
                substitute_name_length = int.from_bytes(data[10:12], 'little')
                
                # Get path (skip header of 16 bytes)
                path_start = 16 + substitute_name_offset
                path_end = path_start + substitute_name_length
                target_path = data[path_start:path_end].decode('utf-16-le')
                
                # Remove \??\ prefix if present
                if target_path.startswith('\\??\\'):
                    target_path = target_path[4:]
                
                return Path(target_path)
                
            finally:
                win32api.CloseHandle(handle)
                
        except Exception as e:
            logger.error(f"Failed to get junction target for {path}: {e}")
            return None
    
    @staticmethod
    def safe_delete(path: Path, force: bool = False) -> bool:
        """
        Safely delete file or directory.
        
        Args:
            path: Path to delete
            force: Force deletion of read-only files
            
        Returns:
            Success status
        """
        try:
            if not path.exists():
                return True
            
            # Handle junctions specially
            if PathUtils.is_junction(path):
                # Remove junction without following it
                path.rmdir()
                return True
            
            # Make writable if forcing
            if force:
                try:
                    path.chmod(0o777)
                except Exception:
                    pass
            
            # Delete based on type
            if path.is_file():
                path.unlink()
            else:
                shutil.rmtree(str(path), ignore_errors=force)
            
            return not path.exists()
            
        except Exception as e:
            logger.error(f"Failed to delete {path}: {e}")
            return False
    
    @staticmethod
    def copy_with_metadata(source: Path, dest: Path, follow_symlinks: bool = True) -> bool:
        """
        Copy file/directory preserving metadata.
        
        Args:
            source: Source path
            dest: Destination path
            follow_symlinks: Whether to follow symbolic links
            
        Returns:
            Success status
        """
        try:
            if source.is_file():
                shutil.copy2(str(source), str(dest), follow_symlinks=follow_symlinks)
            else:
                shutil.copytree(
                    str(source),
                    str(dest),
                    symlinks=not follow_symlinks,
                    copy_function=shutil.copy2
                )
            
            # Copy additional Windows attributes
            try:
                attrs = win32file.GetFileAttributes(str(source))
                win32file.SetFileAttributes(str(dest), attrs)
            except Exception:
                pass
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to copy {source} to {dest}: {e}")
            return False
    
    @staticmethod
    def get_unique_path(base_path: Path, pattern: str = "{name}_{num}{ext}") -> Path:
        """
        Get unique path by appending number if exists.
        
        Args:
            base_path: Base path
            pattern: Pattern for generating names
            
        Returns:
            Unique path that doesn't exist
        """
        if not base_path.exists():
            return base_path
        
        # Split name and extension
        if base_path.is_file():
            name = base_path.stem
            ext = base_path.suffix
        else:
            name = base_path.name
            ext = ""
        
        # Try numbered versions
        num = 1
        while True:
            new_name = pattern.format(name=name, num=num, ext=ext)
            new_path = base_path.parent / new_name
            
            if not new_path.exists():
                return new_path
            
            num += 1
            if num > 1000:  # Safety limit
                raise ValueError("Cannot find unique path")
    
    @staticmethod
    def calculate_directory_size(path: Path, follow_symlinks: bool = True) -> int:
        """
        Calculate total size of directory contents.
        
        Args:
            path: Directory path
            follow_symlinks: Whether to follow symbolic links
            
        Returns:
            Total size in bytes
        """
        total_size = 0
        
        try:
            for entry in path.rglob("*"):
                if entry.is_file(follow_symlinks=follow_symlinks):
                    try:
                        total_size += entry.stat(follow_symlinks=follow_symlinks).st_size
                    except Exception:
                        pass
                        
        except Exception as e:
            logger.error(f"Failed to calculate size of {path}: {e}")
            
        return total_size
    
    @staticmethod
    def get_path_info(path: Path) -> Dict[str, Any]:
        """
        Get detailed information about a path.
        
        Args:
            path: Path to analyze
            
        Returns:
            Dictionary with path information
        """
        info = {
            "exists": path.exists(),
            "type": None,
            "size": 0,
            "is_hidden": False,
            "is_system": False,
            "is_readonly": False,
            "is_junction": False,
            "is_symlink": False,
            "target": None,
        }
        
        if not info["exists"]:
            return info
        
        # Determine type
        if path.is_file():
            info["type"] = "file"
            info["size"] = path.stat().st_size
        elif path.is_dir():
            info["type"] = "directory"
        else:
            info["type"] = "other"
        
        # Check special attributes
        try:
            attrs = win32file.GetFileAttributes(str(path))
            info["is_hidden"] = bool(attrs & win32con.FILE_ATTRIBUTE_HIDDEN)
            info["is_system"] = bool(attrs & win32con.FILE_ATTRIBUTE_SYSTEM)
            info["is_readonly"] = bool(attrs & win32con.FILE_ATTRIBUTE_READONLY)
            
            # Check for reparse points
            if attrs & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
                if PathUtils.is_junction(path):
                    info["is_junction"] = True
                    info["target"] = PathUtils.get_junction_target(path)
                else:
                    info["is_symlink"] = True
                    try:
                        info["target"] = path.readlink()
                    except Exception:
                        pass
        except Exception:
            pass
        
        return info
    
    @staticmethod
    @contextlib.contextmanager
    def temporary_directory(
        suffix: str = None,
        prefix: str = "mcp_",
        dir: Path = None
    ):
        """
        Context manager for temporary directory.
        
        Args:
            suffix: Directory name suffix
            prefix: Directory name prefix
            dir: Parent directory
            
        Yields:
            Path to temporary directory
        """
        temp_dir = None
        try:
            temp_dir = Path(tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dir))
            yield temp_dir
        finally:
            if temp_dir and temp_dir.exists():
                try:
                    shutil.rmtree(str(temp_dir))
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp directory {temp_dir}: {e}")
    
    @staticmethod
    def hash_file(path: Path, algorithm: str = "sha256", chunk_size: int = 65536) -> Optional[str]:
        """
        Calculate file hash.
        
        Args:
            path: File path
            algorithm: Hash algorithm (md5, sha1, sha256, etc.)
            chunk_size: Read chunk size
            
        Returns:
            Hex digest or None on error
        """
        try:
            hasher = hashlib.new(algorithm)
            
            with open(path, "rb") as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
            
            return hasher.hexdigest()
            
        except Exception as e:
            logger.error(f"Failed to hash {path}: {e}")
            return None
    
    @staticmethod
    def resolve_path(
        path: Union[str, Path],
        base_path: Optional[Path] = None,
        strict: bool = False
    ) -> Optional[Path]:
        """
        Resolve path with various strategies.
        
        Args:
            path: Path to resolve
            base_path: Base path for relative paths
            strict: Whether path must exist
            
        Returns:
            Resolved path or None
        """
        try:
            path = Path(path)
            
            # Try as absolute first
            if path.is_absolute():
                if strict:
                    return path if path.exists() else None
                return path
            
            # Try relative to base
            if base_path:
                full_path = base_path / path
                if full_path.exists() or not strict:
                    return full_path.resolve()
            
            # Try relative to current directory
            full_path = Path.cwd() / path
            if full_path.exists() or not strict:
                return full_path.resolve()
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to resolve path {path}: {e}")
            return None


# Convenience functions
def normalize_path(path: Union[str, Path]) -> Path:
    """Normalize a Windows path."""
    return PathUtils.normalize_path(path)


def is_safe_filename(filename: str) -> Tuple[bool, Optional[str]]:
    """Check if filename is safe."""
    return PathUtils.is_safe_filename(filename)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for Windows."""
    return PathUtils.sanitize_filename(filename)


def create_junction(source: Path, target: Path) -> bool:
    """Create Windows junction point."""
    return PathUtils.create_junction(source, target)


def safe_delete(path: Path, force: bool = False) -> bool:
    """Safely delete path."""
    return PathUtils.safe_delete(path, force)


def get_unique_path(base_path: Path) -> Path:
    """Get unique path variant."""
    return PathUtils.get_unique_path(base_path)