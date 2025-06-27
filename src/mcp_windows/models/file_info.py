"""
File information models for MCP Windows Development Server.

This module defines data structures for representing file system objects,
permissions, and metadata.
"""

import os
from datetime import datetime
from enum import Enum, Flag, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, ConfigDict
import structlog

logger = structlog.get_logger(__name__)


class FileType(str, Enum):
    """
    Types of file system objects.
    
    Attributes:
        FILE: Regular file
        DIRECTORY: Directory/folder
        SYMLINK: Symbolic link
        JUNCTION: Windows junction point
        HARDLINK: Hard link
        DEVICE: Device file
        UNKNOWN: Unknown type
    """
    
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    JUNCTION = "junction"
    HARDLINK = "hardlink"
    DEVICE = "device"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_path(cls, path: Path) -> "FileType":
        """Determine file type from path."""
        try:
            if path.is_dir():
                # Check if it's a junction point
                if os.path.islink(str(path)):
                    import win32file
                    attrs = win32file.GetFileAttributes(str(path))
                    if attrs & win32file.FILE_ATTRIBUTE_REPARSE_POINT:
                        return cls.JUNCTION
                return cls.DIRECTORY
            elif path.is_symlink():
                return cls.SYMLINK
            elif path.is_file():
                return cls.FILE
            else:
                return cls.UNKNOWN
        except Exception:
            return cls.UNKNOWN


class FilePermission(Flag):
    """
    Windows file permissions flags.
    
    These map to Windows ACL permissions for file system objects.
    """
    
    # Basic permissions
    READ = auto()
    WRITE = auto()
    EXECUTE = auto()
    DELETE = auto()
    
    # Advanced permissions
    READ_ATTRIBUTES = auto()
    WRITE_ATTRIBUTES = auto()
    READ_EXTENDED = auto()
    WRITE_EXTENDED = auto()
    
    # Directory permissions
    LIST_DIRECTORY = auto()
    ADD_FILE = auto()
    ADD_SUBDIRECTORY = auto()
    TRAVERSE = auto()
    
    # Security permissions
    READ_PERMISSIONS = auto()
    CHANGE_PERMISSIONS = auto()
    TAKE_OWNERSHIP = auto()
    
    # Common combinations
    READ_ONLY = READ | READ_ATTRIBUTES | READ_EXTENDED | READ_PERMISSIONS
    READ_WRITE = READ_ONLY | WRITE | WRITE_ATTRIBUTES | WRITE_EXTENDED
    FULL_CONTROL = ~0  # All permissions
    
    @classmethod
    def from_windows_mask(cls, mask: int) -> "FilePermission":
        """Convert Windows access mask to FilePermission."""
        permission = cls(0)
        
        # Map Windows constants to our permissions
        import win32con
        
        if mask & win32con.FILE_GENERIC_READ:
            permission |= cls.READ | cls.READ_ATTRIBUTES
        if mask & win32con.FILE_GENERIC_WRITE:
            permission |= cls.WRITE | cls.WRITE_ATTRIBUTES
        if mask & win32con.FILE_GENERIC_EXECUTE:
            permission |= cls.EXECUTE | cls.TRAVERSE
        if mask & win32con.DELETE:
            permission |= cls.DELETE
        if mask & win32con.READ_CONTROL:
            permission |= cls.READ_PERMISSIONS
        if mask & win32con.WRITE_DAC:
            permission |= cls.CHANGE_PERMISSIONS
        if mask & win32con.WRITE_OWNER:
            permission |= cls.TAKE_OWNERSHIP
            
        return permission
    
    def to_string(self) -> str:
        """Convert permissions to readable string."""
        parts = []
        if self & FilePermission.READ:
            parts.append("R")
        if self & FilePermission.WRITE:
            parts.append("W")
        if self & FilePermission.EXECUTE:
            parts.append("X")
        if self & FilePermission.DELETE:
            parts.append("D")
        return "".join(parts) if parts else "-"


class FileOwnership(BaseModel):
    """File ownership information."""
    
    model_config = ConfigDict(frozen=True)
    
    owner: str
    owner_sid: Optional[str] = Field(default=None)
    group: Optional[str] = Field(default=None)
    group_sid: Optional[str] = Field(default=None)
    
    @classmethod
    def from_path(cls, path: Path) -> "FileOwnership":
        """Get ownership information from file path."""
        try:
            import win32security
            
            # Get security descriptor
            sd = win32security.GetFileSecurity(
                str(path),
                win32security.OWNER_SECURITY_INFORMATION | 
                win32security.GROUP_SECURITY_INFORMATION
            )
            
            # Get owner
            owner_sid = sd.GetSecurityDescriptorOwner()
            owner_name, owner_domain, _ = win32security.LookupAccountSid(None, owner_sid)
            owner = f"{owner_domain}\\{owner_name}" if owner_domain else owner_name
            
            # Get group
            group_sid = sd.GetSecurityDescriptorGroup()
            group = None
            group_sid_str = None
            if group_sid:
                try:
                    group_name, group_domain, _ = win32security.LookupAccountSid(None, group_sid)
                    group = f"{group_domain}\\{group_name}" if group_domain else group_name
                    group_sid_str = str(group_sid)
                except Exception:
                    pass
            
            return cls(
                owner=owner,
                owner_sid=str(owner_sid),
                group=group,
                group_sid=group_sid_str
            )
        except Exception as e:
            logger.warning(f"Failed to get ownership for {path}: {e}")
            return cls(owner="Unknown", owner_sid=None)


class FileAttributes(BaseModel):
    """Windows file attributes."""
    
    model_config = ConfigDict(frozen=True)
    
    archive: bool = Field(default=False)
    compressed: bool = Field(default=False)
    encrypted: bool = Field(default=False)
    hidden: bool = Field(default=False)
    normal: bool = Field(default=False)
    offline: bool = Field(default=False)
    readonly: bool = Field(default=False)
    system: bool = Field(default=False)
    temporary: bool = Field(default=False)
    
    @classmethod
    def from_windows_attrs(cls, attrs: int) -> "FileAttributes":
        """Create from Windows file attributes."""
        import win32file
        
        return cls(
            archive=bool(attrs & win32file.FILE_ATTRIBUTE_ARCHIVE),
            compressed=bool(attrs & win32file.FILE_ATTRIBUTE_COMPRESSED),
            encrypted=bool(attrs & win32file.FILE_ATTRIBUTE_ENCRYPTED),
            hidden=bool(attrs & win32file.FILE_ATTRIBUTE_HIDDEN),
            normal=bool(attrs & win32file.FILE_ATTRIBUTE_NORMAL),
            offline=bool(attrs & win32file.FILE_ATTRIBUTE_OFFLINE),
            readonly=bool(attrs & win32file.FILE_ATTRIBUTE_READONLY),
            system=bool(attrs & win32file.FILE_ATTRIBUTE_SYSTEM),
            temporary=bool(attrs & win32file.FILE_ATTRIBUTE_TEMPORARY)
        )


class FileInfo(BaseModel):
    """
    Complete file information model.
    
    This model represents all metadata about a file system object including
    type, size, permissions, timestamps, and ownership.
    """
    
    model_config = ConfigDict(validate_assignment=True)
    
    # Path information
    path: Path
    name: str
    extension: Optional[str] = Field(default=None)
    
    # Type and size
    type: FileType
    size: int = Field(default=0, ge=0)
    
    # Timestamps
    created_at: datetime
    modified_at: datetime
    accessed_at: datetime
    
    # Permissions and ownership
    permissions: FilePermission
    ownership: FileOwnership
    attributes: FileAttributes
    
    # Additional metadata
    is_readonly: bool = Field(default=False)
    is_hidden: bool = Field(default=False)
    is_system: bool = Field(default=False)
    link_target: Optional[Path] = Field(default=None)
    
    # Content information (for files)
    mime_type: Optional[str] = Field(default=None)
    encoding: Optional[str] = Field(default=None)
    hash_md5: Optional[str] = Field(default=None)
    hash_sha256: Optional[str] = Field(default=None)
    
    @field_validator("path")
    @classmethod
    def validate_path(cls, v: Path) -> Path:
        """Ensure path is absolute."""
        if not v.is_absolute():
            raise ValueError("Path must be absolute")
        return v
    
    @classmethod
    def from_path(cls, path: Path, calculate_hash: bool = False) -> "FileInfo":
        """
        Create FileInfo from file system path.
        
        Args:
            path: Path to file/directory
            calculate_hash: Whether to calculate file hashes
            
        Returns:
            FileInfo object with metadata
        """
        path = path.resolve()
        stat = path.stat()
        
        # Get Windows-specific attributes
        import win32file
        attrs = win32file.GetFileAttributes(str(path))
        
        # Basic info
        info = cls(
            path=path,
            name=path.name,
            extension=path.suffix.lower() if path.suffix else None,
            type=FileType.from_path(path),
            size=stat.st_size if path.is_file() else 0,
            created_at=datetime.fromtimestamp(stat.st_ctime),
            modified_at=datetime.fromtimestamp(stat.st_mtime),
            accessed_at=datetime.fromtimestamp(stat.st_atime),
            permissions=FilePermission.READ,  # Will be updated
            ownership=FileOwnership.from_path(path),
            attributes=FileAttributes.from_windows_attrs(attrs),
            is_readonly=bool(attrs & win32file.FILE_ATTRIBUTE_READONLY),
            is_hidden=bool(attrs & win32file.FILE_ATTRIBUTE_HIDDEN),
            is_system=bool(attrs & win32file.FILE_ATTRIBUTE_SYSTEM)
        )
        
        # Get actual permissions
        try:
            info.permissions = cls._get_effective_permissions(path)
        except Exception as e:
            logger.warning(f"Failed to get permissions for {path}: {e}")
        
        # Get link target if applicable
        if info.type in (FileType.SYMLINK, FileType.JUNCTION):
            try:
                info.link_target = Path(os.readlink(str(path)))
            except Exception:
                pass
        
        # Get content info for files
        if info.type == FileType.FILE:
            info._update_content_info(calculate_hash)
        
        return info
    
    @staticmethod
    def _get_effective_permissions(path: Path) -> FilePermission:
        """Get effective permissions for current user."""
        permissions = FilePermission(0)
        
        # Check basic access
        if os.access(str(path), os.R_OK):
            permissions |= FilePermission.READ
        if os.access(str(path), os.W_OK):
            permissions |= FilePermission.WRITE
        if os.access(str(path), os.X_OK):
            permissions |= FilePermission.EXECUTE
            
        return permissions
    
    def _update_content_info(self, calculate_hash: bool = False) -> None:
        """Update content-related information."""
        if self.type != FileType.FILE:
            return
            
        # Detect MIME type
        import mimetypes
        mime_type, _ = mimetypes.guess_type(str(self.path))
        self.mime_type = mime_type
        
        # Detect encoding for text files
        if mime_type and mime_type.startswith("text/"):
            try:
                import chardet
                with open(self.path, "rb") as f:
                    result = chardet.detect(f.read(8192))
                    self.encoding = result.get("encoding")
            except Exception:
                pass
        
        # Calculate hashes if requested
        if calculate_hash and self.size < 100 * 1024 * 1024:  # Only for files < 100MB
            try:
                import hashlib
                md5 = hashlib.md5()
                sha256 = hashlib.sha256()
                
                with open(self.path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        md5.update(chunk)
                        sha256.update(chunk)
                
                self.hash_md5 = md5.hexdigest()
                self.hash_sha256 = sha256.hexdigest()
            except Exception as e:
                logger.warning(f"Failed to calculate hash for {self.path}: {e}")
    
    @property
    def is_text_file(self) -> bool:
        """Check if this is a text file."""
        return bool(self.mime_type and self.mime_type.startswith("text/"))
    
    @property
    def is_binary_file(self) -> bool:
        """Check if this is a binary file."""
        return self.type == FileType.FILE and not self.is_text_file
    
    @property
    def size_human(self) -> str:
        """Get human-readable size."""
        size = self.size
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    
    def can_read(self) -> bool:
        """Check if file can be read."""
        return bool(self.permissions & FilePermission.READ)
    
    def can_write(self) -> bool:
        """Check if file can be written."""
        return bool(self.permissions & FilePermission.WRITE) and not self.is_readonly
    
    def can_execute(self) -> bool:
        """Check if file can be executed."""
        return bool(self.permissions & FilePermission.EXECUTE)
    
    def to_dict(self, include_content: bool = True) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        data = self.model_dump(
            exclude={"hash_md5", "hash_sha256"} if not include_content else None
        )
        
        # Convert special types
        data["path"] = str(self.path)
        data["link_target"] = str(self.link_target) if self.link_target else None
        data["type"] = self.type.value
        data["permissions"] = self.permissions.to_string()
        
        # Format timestamps
        for field in ["created_at", "modified_at", "accessed_at"]:
            data[field] = data[field].isoformat()
        
        # Add computed properties
        data["size_human"] = self.size_human
        data["can_read"] = self.can_read()
        data["can_write"] = self.can_write()
        data["can_execute"] = self.can_execute()
        
        return data
    
    def __str__(self) -> str:
        """String representation."""
        return f"FileInfo({self.type.value}: {self.path})"


class DirectoryListing(BaseModel):
    """Result of listing a directory."""
    
    model_config = ConfigDict(frozen=True)
    
    path: Path
    total_items: int
    total_size: int
    items: List[FileInfo]
    
    @property
    def total_size_human(self) -> str:
        """Get human-readable total size."""
        size = self.total_size
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    
    @property
    def file_count(self) -> int:
        """Get number of files."""
        return sum(1 for item in self.items if item.type == FileType.FILE)
    
    @property
    def directory_count(self) -> int:
        """Get number of directories."""
        return sum(1 for item in self.items if item.type == FileType.DIRECTORY)
    
    def filter_by_type(self, file_type: FileType) -> List[FileInfo]:
        """Filter items by type."""
        return [item for item in self.items if item.type == file_type]
    
    def filter_by_extension(self, extension: str) -> List[FileInfo]:
        """Filter items by extension."""
        ext = extension.lower() if not extension.startswith(".") else extension.lower()
        return [item for item in self.items if item.extension == ext]