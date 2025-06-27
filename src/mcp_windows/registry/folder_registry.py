"""
Folder registry for MCP Windows Development Server.

This module manages the registry of authorized folders with their permission
levels and integrates with Windows Registry for persistence.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime
from uuid import UUID
import winreg

import structlog

from ..config.settings import MCPWindowsSettings
from ..models.registry_entry import RegistryEntry, PermissionLevel, FolderRestriction
from ..utils.logging_config import get_logger, AuditLogger
from ..utils.path_utils import PathUtils
from ..utils.security_utils import SecurityUtils

logger = get_logger(__name__)


class RegistryInterface:
    """Windows Registry interface for persistence."""
    
    def __init__(self, base_key: str = r"SOFTWARE\MCPWindows\AuthorizedFolders"):
        """
        Initialize registry interface.
        
        Args:
            base_key: Base registry key path
        """
        self.base_key = base_key
        self._ensure_key_exists()
    
    def _ensure_key_exists(self) -> None:
        """Ensure registry key exists."""
        try:
            # Try to create key under HKEY_CURRENT_USER first
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.base_key):
                pass
        except Exception:
            # Try HKEY_LOCAL_MACHINE if admin
            try:
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, self.base_key):
                    pass
            except Exception as e:
                logger.warning(
                    "Failed to create registry key",
                    key=self.base_key,
                    error=str(e)
                )
    
    def save_entry(self, entry: RegistryEntry) -> bool:
        """
        Save registry entry to Windows Registry.
        
        Args:
            entry: Registry entry to save
            
        Returns:
            Success status
        """
        try:
            # Try HKEY_CURRENT_USER first
            root_key = winreg.HKEY_CURRENT_USER
            
            try:
                key = winreg.CreateKey(root_key, self.base_key)
            except Exception:
                # Try HKEY_LOCAL_MACHINE if admin
                root_key = winreg.HKEY_LOCAL_MACHINE
                key = winreg.CreateKey(root_key, self.base_key)
            
            with key:
                # Create subkey for this entry
                entry_key_name = f"{self.base_key}\\{entry.id}"
                with winreg.CreateKey(root_key, entry_key_name) as entry_key:
                    # Save entry data
                    data = entry.to_registry_value()
                    
                    for name, value in data.items():
                        # Determine value type
                        if isinstance(value, int):
                            winreg.SetValueEx(
                                entry_key, name, 0, winreg.REG_DWORD, value
                            )
                        elif isinstance(value, bool):
                            winreg.SetValueEx(
                                entry_key, name, 0, winreg.REG_DWORD, int(value)
                            )
                        else:
                            winreg.SetValueEx(
                                entry_key, name, 0, winreg.REG_SZ, str(value)
                            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to save registry entry",
                entry_id=str(entry.id),
                error=str(e)
            )
            return False
    
    def load_entry(self, entry_id: UUID) -> Optional[RegistryEntry]:
        """
        Load registry entry from Windows Registry.
        
        Args:
            entry_id: Entry ID to load
            
        Returns:
            Registry entry or None
        """
        # Try both registry roots
        for root_key in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            try:
                entry_key_name = f"{self.base_key}\\{entry_id}"
                with winreg.OpenKey(root_key, entry_key_name) as entry_key:
                    # Read all values
                    data = {}
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(entry_key, i)
                            data[name] = value
                            i += 1
                        except WindowsError:
                            break
                    
                    # Reconstruct entry
                    return RegistryEntry.from_registry_value(data)
                    
            except Exception:
                continue
        
        return None
    
    def delete_entry(self, entry_id: UUID) -> bool:
        """
        Delete registry entry.
        
        Args:
            entry_id: Entry ID to delete
            
        Returns:
            Success status
        """
        deleted = False
        
        # Try both registry roots
        for root_key in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            try:
                entry_key_name = f"{self.base_key}\\{entry_id}"
                winreg.DeleteKey(root_key, entry_key_name)
                deleted = True
            except Exception:
                continue
        
        return deleted
    
    def list_entries(self) -> List[UUID]:
        """
        List all registry entry IDs.
        
        Returns:
            List of entry IDs
        """
        entry_ids = set()
        
        # Try both registry roots
        for root_key in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            try:
                with winreg.OpenKey(root_key, self.base_key) as key:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            # Try to parse as UUID
                            try:
                                entry_id = UUID(subkey_name)
                                entry_ids.add(entry_id)
                            except ValueError:
                                pass
                            i += 1
                        except WindowsError:
                            break
            except Exception:
                continue
        
        return list(entry_ids)


class FolderRegistry:
    """
    Registry for authorized folders.
    
    This class manages:
    - Folder authorization and permissions
    - Integration with Windows Registry
    - Permission validation and enforcement
    - Usage tracking and auditing
    """
    
    def __init__(self, settings: MCPWindowsSettings):
        """
        Initialize folder registry.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self._registry_interface = RegistryInterface(settings.registry_key + "\\Folders")
        
        # In-memory cache
        self._entries: Dict[UUID, RegistryEntry] = {}
        self._path_index: Dict[Path, UUID] = {}  # For quick path lookups
        
        # Audit logger
        self._audit_logger = AuditLogger(
            Path(settings.workspace.root_directory) / ".audit" / "registry.log"
        )
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
        
        # Security utils
        self._security_utils = SecurityUtils()
        
        logger.info(
            "Folder registry initialized",
            registry_key=settings.registry_key
        )
    
    async def initialize(self) -> None:
        """Initialize registry and load existing entries."""
        async with self._lock:
            # Load entries from registry
            entry_ids = await asyncio.to_thread(self._registry_interface.list_entries)
            loaded = 0
            
            for entry_id in entry_ids:
                try:
                    entry = await asyncio.to_thread(
                        self._registry_interface.load_entry,
                        entry_id
                    )
                    
                    if entry and entry.path.exists():
                        self._entries[entry.id] = entry
                        self._path_index[entry.path] = entry.id
                        loaded += 1
                except Exception as e:
                    logger.error(
                        "Failed to load registry entry",
                        entry_id=str(entry_id),
                        error=str(e)
                    )
            
            logger.info(
                "Loaded registry entries",
                count=loaded,
                total=len(entry_ids)
            )
            
            # Add default authorized folders
            await self._add_default_folders()
    
    async def authorize_folder(
        self,
        folder_path: Path,
        permission_level: PermissionLevel,
        description: Optional[str] = None,
        restrictions: Optional[FolderRestriction] = None,
        tags: Optional[Set[str]] = None,
        expires_at: Optional[datetime] = None
    ) -> RegistryEntry:
        """
        Authorize a folder for access.
        
        Args:
            folder_path: Path to authorize
            permission_level: Permission level to grant
            description: Optional description
            restrictions: Optional restrictions
            tags: Optional tags
            expires_at: Optional expiration time
            
        Returns:
            Created registry entry
            
        Raises:
            ValueError: If path invalid or already authorized
        """
        async with self._lock:
            # Normalize and validate path
            folder_path = PathUtils.normalize_path(folder_path)
            
            if not folder_path.exists():
                raise ValueError(f"Path does not exist: {folder_path}")
            
            if not folder_path.is_dir():
                raise ValueError(f"Path must be a directory: {folder_path}")
            
            # Check if already authorized
            if folder_path in self._path_index:
                existing_id = self._path_index[folder_path]
                existing = self._entries[existing_id]
                raise ValueError(
                    f"Folder already authorized with {existing.permission_level} permission"
                )
            
            # Create registry entry
            entry = RegistryEntry(
                path=folder_path,
                permission_level=permission_level,
                description=description,
                restrictions=restrictions or FolderRestriction(),
                tags=tags or set(),
                created_by=self._security_utils.get_current_user()[0],
                expires_at=expires_at
            )
            
            # Save to registry
            success = await asyncio.to_thread(
                self._registry_interface.save_entry,
                entry
            )
            
            if not success:
                raise RuntimeError("Failed to save entry to registry")
            
            # Add to cache
            self._entries[entry.id] = entry
            self._path_index[folder_path] = entry.id
            
            # Audit log
            self._audit_logger.log_permission_change(
                str(folder_path),
                "none",
                str(permission_level),
                entry.created_by
            )
            
            logger.info(
                "Authorized folder",
                path=str(folder_path),
                permission=str(permission_level),
                entry_id=str(entry.id)
            )
            
            return entry
    
    async def revoke_folder_access(self, folder_path: Path) -> bool:
        """
        Revoke folder authorization.
        
        Args:
            folder_path: Path to revoke
            
        Returns:
            Success status
        """
        async with self._lock:
            # Normalize path
            folder_path = PathUtils.normalize_path(folder_path)
            
            # Find entry
            entry_id = self._path_index.get(folder_path)
            if not entry_id:
                logger.warning(
                    "Attempted to revoke non-authorized folder",
                    path=str(folder_path)
                )
                return False
            
            entry = self._entries.get(entry_id)
            if not entry:
                return False
            
            # Delete from registry
            success = await asyncio.to_thread(
                self._registry_interface.delete_entry,
                entry_id
            )
            
            if success:
                # Remove from cache
                del self._entries[entry_id]
                del self._path_index[folder_path]
                
                # Audit log
                self._audit_logger.log_permission_change(
                    str(folder_path),
                    str(entry.permission_level),
                    "none",
                    self._security_utils.get_current_user()[0]
                )
                
                logger.info(
                    "Revoked folder access",
                    path=str(folder_path),
                    entry_id=str(entry_id)
                )
            
            return success
    
    async def update_folder_permissions(
        self,
        folder_path: Path,
        new_permission_level: PermissionLevel
    ) -> bool:
        """
        Update folder permission level.
        
        Args:
            folder_path: Path to update
            new_permission_level: New permission level
            
        Returns:
            Success status
        """
        async with self._lock:
            # Normalize path
            folder_path = PathUtils.normalize_path(folder_path)
            
            # Find entry
            entry_id = self._path_index.get(folder_path)
            if not entry_id:
                return False
            
            entry = self._entries.get(entry_id)
            if not entry:
                return False
            
            # Update permission
            old_level = entry.permission_level
            entry.update_permission(
                new_permission_level,
                self._security_utils.get_current_user()[0]
            )
            
            # Save to registry
            success = await asyncio.to_thread(
                self._registry_interface.save_entry,
                entry
            )
            
            if success:
                logger.info(
                    "Updated folder permissions",
                    path=str(folder_path),
                    old_level=str(old_level),
                    new_level=str(new_permission_level)
                )
            
            return success
    
    async def list_authorized_folders(
        self,
        include_expired: bool = False,
        permission_level: Optional[PermissionLevel] = None
    ) -> List[RegistryEntry]:
        """
        List all authorized folders.
        
        Args:
            include_expired: Include expired entries
            permission_level: Filter by permission level
            
        Returns:
            List of registry entries
        """
        async with self._lock:
            entries = []
            
            for entry in self._entries.values():
                # Filter expired
                if not include_expired and entry.is_expired:
                    continue
                
                # Filter by permission
                if permission_level and entry.permission_level != permission_level:
                    continue
                
                entries.append(entry)
            
            return sorted(entries, key=lambda e: e.created_at, reverse=True)
    
    async def check_path_authorization(
        self,
        path: Path,
        required_permission: PermissionLevel
    ) -> Tuple[bool, Optional[RegistryEntry], Optional[str]]:
        """
        Check if path is authorized for access.
        
        Args:
            path: Path to check
            required_permission: Required permission level
            
        Returns:
            Tuple of (authorized, matching_entry, reason_if_not)
        """
        async with self._lock:
            # Normalize path
            path = PathUtils.normalize_path(path)
            
            # Check each authorized folder
            best_match = None
            best_match_depth = -1
            
            for entry in self._entries.values():
                # Skip inactive entries
                if not entry.is_active:
                    continue
                
                # Check if path is under this folder
                try:
                    rel_path = path.relative_to(entry.path)
                    
                    # Calculate match depth (prefer more specific matches)
                    depth = len(entry.path.parts)
                    
                    if depth > best_match_depth:
                        best_match = entry
                        best_match_depth = depth
                        
                except ValueError:
                    # Path not under this folder
                    continue
            
            if not best_match:
                return False, None, "Path is not under any authorized folder"
            
            # Check permission level
            effective_permission = best_match.effective_permission
            if effective_permission < required_permission:
                return (
                    False,
                    best_match,
                    f"Insufficient permissions: have {effective_permission}, need {required_permission}"
                )
            
            # Check file restrictions
            if path.is_file() or not path.exists():
                allowed, reason = best_match.check_file_allowed(path)
                if not allowed:
                    return False, best_match, reason
            
            # Record access
            best_match.record_access()
            
            return True, best_match, None
    
    async def get_authorized_folders_for_session(
        self,
        session_permissions: PermissionLevel
    ) -> List[Tuple[str, Path, PermissionLevel]]:
        """
        Get folders authorized for a session.
        
        Args:
            session_permissions: Session's permission level
            
        Returns:
            List of (name, path, effective_permission) tuples
        """
        async with self._lock:
            authorized = []
            
            for entry in self._entries.values():
                # Skip inactive
                if not entry.is_active:
                    continue
                
                # Determine effective permission
                effective = min(entry.effective_permission, session_permissions)
                
                if effective > PermissionLevel.NO_ACCESS:
                    name = entry.description or entry.path.name
                    authorized.append((name, entry.path, effective))
            
            return authorized
    
    async def cleanup_expired_entries(self) -> int:
        """
        Clean up expired registry entries.
        
        Returns:
            Number of entries cleaned
        """
        async with self._lock:
            cleaned = 0
            
            for entry_id, entry in list(self._entries.items()):
                if entry.is_expired:
                    # Delete from registry
                    success = await asyncio.to_thread(
                        self._registry_interface.delete_entry,
                        entry_id
                    )
                    
                    if success:
                        # Remove from cache
                        del self._entries[entry_id]
                        if entry.path in self._path_index:
                            del self._path_index[entry.path]
                        
                        cleaned += 1
                        
                        logger.info(
                            "Cleaned up expired entry",
                            path=str(entry.path),
                            entry_id=str(entry_id)
                        )
            
            return cleaned
    
    async def export_registry(self) -> Dict[str, Any]:
        """
        Export registry to dictionary format.
        
        Returns:
            Registry data
        """
        async with self._lock:
            return {
                "version": "1.0",
                "exported_at": datetime.utcnow().isoformat(),
                "exported_by": self._security_utils.get_current_user()[0],
                "entries": [
                    entry.to_registry_value()
                    for entry in self._entries.values()
                ]
            }
    
    async def import_registry(
        self,
        data: Dict[str, Any],
        merge: bool = True
    ) -> Tuple[int, int]:
        """
        Import registry from dictionary format.
        
        Args:
            data: Registry data to import
            merge: Merge with existing entries
            
        Returns:
            Tuple of (imported, failed)
        """
        async with self._lock:
            imported = 0
            failed = 0
            
            # Clear existing if not merging
            if not merge:
                for entry_id in list(self._entries.keys()):
                    await self.revoke_folder_access(
                        self._entries[entry_id].path
                    )
            
            # Import entries
            for entry_data in data.get("entries", []):
                try:
                    entry = RegistryEntry.from_registry_value(entry_data)
                    
                    # Check if already exists
                    if entry.path in self._path_index:
                        if merge:
                            # Update existing
                            existing_id = self._path_index[entry.path]
                            self._entries[existing_id] = entry
                        else:
                            failed += 1
                            continue
                    else:
                        # Add new
                        self._entries[entry.id] = entry
                        self._path_index[entry.path] = entry.id
                    
                    # Save to registry
                    await asyncio.to_thread(
                        self._registry_interface.save_entry,
                        entry
                    )
                    
                    imported += 1
                    
                except Exception as e:
                    logger.error(
                        "Failed to import registry entry",
                        error=str(e)
                    )
                    failed += 1
            
            logger.info(
                "Imported registry entries",
                imported=imported,
                failed=failed
            )
            
            return imported, failed
    
    async def _add_default_folders(self) -> None:
        """Add default authorized folders."""
        # Default folders to authorize
        defaults = [
            # User directories
            (Path.home() / "Documents", PermissionLevel.READ_ONLY, "User Documents"),
            (Path.home() / "Downloads", PermissionLevel.READ_ONLY, "User Downloads"),
            
            # Common development directories
            (Path("C:/Projects"), PermissionLevel.READ_WRITE, "Projects Directory"),
            (Path("C:/Development"), PermissionLevel.READ_WRITE, "Development Directory"),
        ]
        
        for path, permission, description in defaults:
            if path.exists():
                try:
                    await self.authorize_folder(
                        path,
                        permission,
                        description=description,
                        tags={"default", "auto"}
                    )
                except ValueError:
                    # Already authorized
                    pass
                except Exception as e:
                    logger.debug(
                        f"Failed to add default folder {path}: {e}"
                    )