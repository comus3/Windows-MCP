"""
Registry entry models for MCP Windows Development Server.

This module defines data structures for managing folder authorization registry
entries and permission configurations.
"""

from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict
import structlog

logger = structlog.get_logger(__name__)


class PermissionLevel(IntEnum):
    """
    Permission levels for folder access.
    
    These levels are hierarchical - higher levels include all permissions
    from lower levels.
    
    Attributes:
        NO_ACCESS: No access allowed
        READ_ONLY: Can read files and list directories
        READ_WRITE: Can read and modify files
        EXECUTE: Can run programs and scripts
        FULL_CONTROL: Complete access including permission changes
    """
    
    NO_ACCESS = 0
    READ_ONLY = 1
    READ_WRITE = 2
    EXECUTE = 3
    FULL_CONTROL = 4
    
    @classmethod
    def from_string(cls, value: str) -> "PermissionLevel":
        """Convert string to PermissionLevel."""
        mapping = {
            "none": cls.NO_ACCESS,
            "no_access": cls.NO_ACCESS,
            "read": cls.READ_ONLY,
            "read_only": cls.READ_ONLY,
            "read_write": cls.READ_WRITE,
            "write": cls.READ_WRITE,
            "execute": cls.EXECUTE,
            "exec": cls.EXECUTE,
            "full": cls.FULL_CONTROL,
            "full_control": cls.FULL_CONTROL,
            "admin": cls.FULL_CONTROL,
        }
        
        normalized = value.lower().replace("-", "_")
        if normalized in mapping:
            return mapping[normalized]
        
        # Try to parse as integer
        try:
            level = int(value)
            if 0 <= level <= 4:
                return cls(level)
        except ValueError:
            pass
        
        raise ValueError(
            f"Invalid permission level: {value}. "
            f"Valid values: {', '.join(mapping.keys())} or 0-4"
        )
    
    def includes(self, other: "PermissionLevel") -> bool:
        """Check if this level includes another level's permissions."""
        return self >= other
    
    @property
    def can_read(self) -> bool:
        """Check if this level allows reading."""
        return self >= PermissionLevel.READ_ONLY
    
    @property
    def can_write(self) -> bool:
        """Check if this level allows writing."""
        return self >= PermissionLevel.READ_WRITE
    
    @property
    def can_execute(self) -> bool:
        """Check if this level allows execution."""
        return self >= PermissionLevel.EXECUTE
    
    @property
    def can_change_permissions(self) -> bool:
        """Check if this level allows changing permissions."""
        return self == PermissionLevel.FULL_CONTROL
    
    def to_windows_mask(self) -> int:
        """Convert to Windows access mask."""
        import win32con
        
        if self == PermissionLevel.NO_ACCESS:
            return 0
        elif self == PermissionLevel.READ_ONLY:
            return (
                win32con.FILE_GENERIC_READ |
                win32con.FILE_LIST_DIRECTORY |
                win32con.FILE_TRAVERSE
            )
        elif self == PermissionLevel.READ_WRITE:
            return (
                win32con.FILE_GENERIC_READ |
                win32con.FILE_GENERIC_WRITE |
                win32con.FILE_LIST_DIRECTORY |
                win32con.FILE_ADD_FILE |
                win32con.FILE_ADD_SUBDIRECTORY |
                win32con.FILE_TRAVERSE |
                win32con.DELETE
            )
        elif self == PermissionLevel.EXECUTE:
            return (
                win32con.FILE_GENERIC_READ |
                win32con.FILE_GENERIC_WRITE |
                win32con.FILE_GENERIC_EXECUTE |
                win32con.FILE_LIST_DIRECTORY |
                win32con.FILE_ADD_FILE |
                win32con.FILE_ADD_SUBDIRECTORY |
                win32con.FILE_TRAVERSE |
                win32con.DELETE
            )
        else:  # FULL_CONTROL
            return win32con.GENERIC_ALL
    
    def __str__(self) -> str:
        """String representation."""
        return self.name.lower()


class FolderRestriction(BaseModel):
    """Additional restrictions for a folder."""
    
    model_config = ConfigDict(frozen=True)
    
    # File type restrictions
    allowed_extensions: Set[str] = Field(default_factory=set)
    blocked_extensions: Set[str] = Field(default_factory=set)
    
    # Size restrictions
    max_file_size_mb: Optional[int] = Field(default=None, ge=1, le=10240)
    max_total_size_mb: Optional[int] = Field(default=None, ge=1, le=102400)
    
    # Operation restrictions
    allow_hidden_files: bool = Field(default=True)
    allow_system_files: bool = Field(default=False)
    allow_symbolic_links: bool = Field(default=True)
    allow_junction_points: bool = Field(default=True)
    
    # Time restrictions
    read_only_after_hours: bool = Field(default=False)
    business_hours_start: Optional[int] = Field(default=None, ge=0, le=23)
    business_hours_end: Optional[int] = Field(default=None, ge=0, le=23)
    
    @field_validator("allowed_extensions", "blocked_extensions")
    @classmethod
    def normalize_extensions(cls, v: Set[str]) -> Set[str]:
        """Normalize file extensions."""
        normalized = set()
        for ext in v:
            ext = ext.lower().strip()
            if not ext.startswith("."):
                ext = f".{ext}"
            normalized.add(ext)
        return normalized
    
    @model_validator(mode="after")
    def validate_extensions(self) -> "FolderRestriction":
        """Ensure allowed and blocked extensions don't overlap."""
        overlap = self.allowed_extensions & self.blocked_extensions
        if overlap:
            raise ValueError(
                f"Extensions cannot be both allowed and blocked: {overlap}"
            )
        return self
    
    def is_extension_allowed(self, extension: str) -> bool:
        """Check if file extension is allowed."""
        if not extension:
            return True
            
        ext = extension.lower()
        if not ext.startswith("."):
            ext = f".{ext}"
        
        # If we have an allowlist, extension must be in it
        if self.allowed_extensions:
            return ext in self.allowed_extensions
        
        # Otherwise, check blocklist
        return ext not in self.blocked_extensions
    
    def is_within_business_hours(self) -> bool:
        """Check if current time is within business hours."""
        if not self.read_only_after_hours:
            return True
            
        if self.business_hours_start is None or self.business_hours_end is None:
            return True
            
        current_hour = datetime.now().hour
        
        # Handle case where end time is next day (e.g., 22-6)
        if self.business_hours_end < self.business_hours_start:
            return (
                current_hour >= self.business_hours_start or
                current_hour < self.business_hours_end
            )
        else:
            return (
                self.business_hours_start <= current_hour < self.business_hours_end
            )


class RegistryEntry(BaseModel):
    """
    Registry entry for an authorized folder.
    
    This model represents a folder that has been authorized for access
    with specific permissions and restrictions.
    """
    
    model_config = ConfigDict(validate_assignment=True)
    
    # Identity
    id: UUID = Field(default_factory=uuid4)
    path: Path
    
    # Permissions
    permission_level: PermissionLevel
    inherit_permissions: bool = Field(default=True)
    
    # Metadata
    description: Optional[str] = Field(default=None, max_length=500)
    tags: Set[str] = Field(default_factory=set)
    
    # Restrictions
    restrictions: FolderRestriction = Field(default_factory=FolderRestriction)
    
    # Audit info
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = Field(default="system")
    modified_at: datetime = Field(default_factory=datetime.utcnow)
    modified_by: str = Field(default="system")
    
    # Usage tracking
    last_accessed_at: Optional[datetime] = Field(default=None)
    access_count: int = Field(default=0, ge=0)
    
    # Status
    enabled: bool = Field(default=True)
    expires_at: Optional[datetime] = Field(default=None)
    
    @field_validator("path")
    @classmethod
    def validate_path(cls, v: Path) -> Path:
        """Ensure path is absolute and exists."""
        if not v.is_absolute():
            raise ValueError("Path must be absolute")
        
        # Convert to Path object if string
        path = Path(v) if isinstance(v, str) else v
        
        # Normalize path
        path = path.resolve()
        
        # Check existence
        if not path.exists():
            raise ValueError(f"Path does not exist: {path}")
        
        if not path.is_dir():
            raise ValueError(f"Path must be a directory: {path}")
        
        return path
    
    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, v: Set[str]) -> Set[str]:
        """Normalize tags."""
        return {tag.lower().strip() for tag in v if tag.strip()}
    
    @property
    def is_active(self) -> bool:
        """Check if entry is currently active."""
        if not self.enabled:
            return False
            
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
            
        return True
    
    @property
    def is_expired(self) -> bool:
        """Check if entry has expired."""
        return self.expires_at is not None and datetime.utcnow() > self.expires_at
    
    @property
    def effective_permission(self) -> PermissionLevel:
        """Get effective permission level considering restrictions."""
        if not self.is_active:
            return PermissionLevel.NO_ACCESS
            
        # Check business hours restriction
        if (self.restrictions.read_only_after_hours and 
            not self.restrictions.is_within_business_hours()):
            return min(self.permission_level, PermissionLevel.READ_ONLY)
            
        return self.permission_level
    
    def update_permission(
        self,
        new_level: PermissionLevel,
        modified_by: str = "system"
    ) -> None:
        """
        Update permission level.
        
        Args:
            new_level: New permission level
            modified_by: User making the change
        """
        old_level = self.permission_level
        self.permission_level = new_level
        self.modified_at = datetime.utcnow()
        self.modified_by = modified_by
        
        logger.info(
            "Registry entry permission updated",
            entry_id=str(self.id),
            path=str(self.path),
            old_level=str(old_level),
            new_level=str(new_level),
            modified_by=modified_by
        )
    
    def record_access(self) -> None:
        """Record an access to this folder."""
        self.last_accessed_at = datetime.utcnow()
        self.access_count += 1
    
    def check_file_allowed(self, file_path: Path) -> tuple[bool, Optional[str]]:
        """
        Check if a file is allowed under this entry's restrictions.
        
        Args:
            file_path: Path to check
            
        Returns:
            Tuple of (allowed, reason_if_not)
        """
        # Check if path is under this folder
        try:
            file_path.relative_to(self.path)
        except ValueError:
            return False, "Path is not under authorized folder"
        
        # Check extension
        if file_path.suffix:
            if not self.restrictions.is_extension_allowed(file_path.suffix):
                return False, f"File extension {file_path.suffix} is not allowed"
        
        # Check file attributes
        if file_path.exists():
            try:
                import win32file
                attrs = win32file.GetFileAttributes(str(file_path))
                
                if (not self.restrictions.allow_hidden_files and
                    attrs & win32file.FILE_ATTRIBUTE_HIDDEN):
                    return False, "Hidden files are not allowed"
                
                if (not self.restrictions.allow_system_files and
                    attrs & win32file.FILE_ATTRIBUTE_SYSTEM):
                    return False, "System files are not allowed"
            except Exception:
                pass
        
        return True, None
    
    def to_registry_value(self) -> Dict[str, Any]:
        """Convert to Windows Registry value format."""
        return {
            "id": str(self.id),
            "path": str(self.path),
            "permission_level": int(self.permission_level),
            "inherit_permissions": self.inherit_permissions,
            "description": self.description or "",
            "tags": ";".join(sorted(self.tags)),
            "restrictions": self.restrictions.model_dump_json(),
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "modified_at": self.modified_at.isoformat(),
            "modified_by": self.modified_by,
            "enabled": self.enabled,
            "expires_at": self.expires_at.isoformat() if self.expires_at else "",
            "access_count": self.access_count,
            "last_accessed_at": (
                self.last_accessed_at.isoformat() if self.last_accessed_at else ""
            ),
        }
    
    @classmethod
    def from_registry_value(cls, data: Dict[str, Any]) -> "RegistryEntry":
        """Create from Windows Registry value format."""
        import json
        
        # Parse restrictions
        restrictions = FolderRestriction()
        if data.get("restrictions"):
            try:
                restrictions = FolderRestriction.model_validate_json(data["restrictions"])
            except Exception as e:
                logger.warning(f"Failed to parse restrictions: {e}")
        
        # Parse timestamps
        def parse_timestamp(value: str) -> Optional[datetime]:
            if not value:
                return None
            try:
                return datetime.fromisoformat(value)
            except Exception:
                return None
        
        return cls(
            id=UUID(data["id"]),
            path=Path(data["path"]),
            permission_level=PermissionLevel(data["permission_level"]),
            inherit_permissions=data.get("inherit_permissions", True),
            description=data.get("description") or None,
            tags=set(data.get("tags", "").split(";")) if data.get("tags") else set(),
            restrictions=restrictions,
            created_at=parse_timestamp(data["created_at"]) or datetime.utcnow(),
            created_by=data.get("created_by", "system"),
            modified_at=parse_timestamp(data["modified_at"]) or datetime.utcnow(),
            modified_by=data.get("modified_by", "system"),
            enabled=data.get("enabled", True),
            expires_at=parse_timestamp(data.get("expires_at")),
            access_count=data.get("access_count", 0),
            last_accessed_at=parse_timestamp(data.get("last_accessed_at"))
        )
    
    def __str__(self) -> str:
        """String representation."""
        return (
            f"RegistryEntry(path={self.path}, "
            f"permission={self.permission_level}, "
            f"active={self.is_active})"
        )