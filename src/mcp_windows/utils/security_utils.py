"""
Security utilities for MCP Windows Development Server.

This module provides helper functions for Windows security operations including
ACL management, SID lookups, privilege checks, and permission validation.
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from enum import IntEnum
import ctypes
from ctypes import wintypes

import win32api
import win32con
import win32security
import win32file
import ntsecuritycon
import pywintypes
import structlog

logger = structlog.get_logger(__name__)


class PrivilegeLevel(IntEnum):
    """Windows privilege levels."""
    
    GUEST = 0
    USER = 1
    POWER_USER = 2
    ADMINISTRATOR = 3
    SYSTEM = 4


class SecurityUtils:
    """Utility class for Windows security operations."""
    
    # Common SID strings
    EVERYONE_SID = "S-1-1-0"
    USERS_SID = "S-1-5-32-545"
    ADMINISTRATORS_SID = "S-1-5-32-544"
    SYSTEM_SID = "S-1-5-18"
    
    @staticmethod
    def get_current_user() -> Tuple[str, str]:
        """
        Get current user name and domain.
        
        Returns:
            Tuple of (username, domain)
        """
        try:
            username = win32api.GetUserName()
            domain = win32api.GetDomainName()
            return username, domain
        except Exception as e:
            logger.error(f"Failed to get current user: {e}")
            return "Unknown", "Unknown"
    
    @staticmethod
    def get_current_user_sid() -> Optional[str]:
        """
        Get current user's SID string.
        
        Returns:
            SID string or None on error
        """
        try:
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_QUERY
            )
            sid = win32security.GetTokenInformation(
                token,
                win32security.TokenUser
            )[0]
            return win32security.ConvertSidToStringSid(sid)
        except Exception as e:
            logger.error(f"Failed to get current user SID: {e}")
            return None
    
    @staticmethod
    def is_admin() -> bool:
        """Check if current process has administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    
    @staticmethod
    def get_privilege_level() -> PrivilegeLevel:
        """Get current user's privilege level."""
        if SecurityUtils.is_system():
            return PrivilegeLevel.SYSTEM
        elif SecurityUtils.is_admin():
            return PrivilegeLevel.ADMINISTRATOR
        else:
            # Check if user is in Power Users group
            try:
                groups = SecurityUtils.get_user_groups()
                if any("Power Users" in g for g in groups):
                    return PrivilegeLevel.POWER_USER
            except Exception:
                pass
            
            return PrivilegeLevel.USER
    
    @staticmethod
    def is_system() -> bool:
        """Check if running as SYSTEM account."""
        try:
            current_sid = SecurityUtils.get_current_user_sid()
            return current_sid == SecurityUtils.SYSTEM_SID
        except Exception:
            return False
    
    @staticmethod
    def get_user_groups() -> List[str]:
        """Get list of groups current user belongs to."""
        groups = []
        try:
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_QUERY
            )
            group_sids = win32security.GetTokenInformation(
                token,
                win32security.TokenGroups
            )
            
            for sid, attributes in group_sids:
                try:
                    name, domain, _ = win32security.LookupAccountSid(None, sid)
                    group_name = f"{domain}\\{name}" if domain else name
                    groups.append(group_name)
                except Exception:
                    # Some SIDs might not resolve
                    pass
                    
        except Exception as e:
            logger.error(f"Failed to get user groups: {e}")
            
        return groups
    
    @staticmethod
    def create_security_descriptor(
        owner_sid: Optional[Any] = None,
        group_sid: Optional[Any] = None,
        dacl_entries: Optional[List[Tuple[Any, int, int]]] = None
    ) -> win32security.SECURITY_DESCRIPTOR:
        """
        Create a security descriptor with specified permissions.
        
        Args:
            owner_sid: Owner SID (defaults to current user)
            group_sid: Group SID (defaults to None)
            dacl_entries: List of (sid, access_mask, ace_type) tuples
            
        Returns:
            Security descriptor object
        """
        sd = win32security.SECURITY_DESCRIPTOR()
        
        # Set owner
        if owner_sid is None:
            owner_sid = win32security.GetTokenInformation(
                win32security.OpenProcessToken(
                    win32api.GetCurrentProcess(),
                    win32con.TOKEN_QUERY
                ),
                win32security.TokenUser
            )[0]
        sd.SetSecurityDescriptorOwner(owner_sid, False)
        
        # Set group if provided
        if group_sid:
            sd.SetSecurityDescriptorGroup(group_sid, False)
        
        # Create DACL
        if dacl_entries:
            dacl = win32security.ACL()
            for sid, access_mask, ace_type in dacl_entries:
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    access_mask,
                    sid
                )
            sd.SetSecurityDescriptorDacl(True, dacl, False)
        
        return sd
    
    @staticmethod
    def set_file_permissions(
        path: Path,
        owner_sid: Optional[win32security.PySID] = None,
        permissions: Optional[Dict[str, int]] = None,
        inherit: bool = True
    ) -> bool:
        """
        Set file/directory permissions.
        
        Args:
            path: Path to file/directory
            owner_sid: Owner SID (defaults to current user)
            permissions: Dict of SID string to access mask
            inherit: Whether to enable inheritance
            
        Returns:
            Success status
        """
        try:
            # Get current security descriptor
            sd = win32security.GetFileSecurity(
                str(path),
                win32security.DACL_SECURITY_INFORMATION |
                win32security.OWNER_SECURITY_INFORMATION
            )
            
            # Set owner if specified
            if owner_sid:
                sd.SetSecurityDescriptorOwner(owner_sid, False)
            
            # Create new DACL if permissions specified
            if permissions:
                dacl = win32security.ACL()
                
                for sid_str, access_mask in permissions.items():
                    try:
                        if sid_str.startswith("S-"):
                            sid = win32security.ConvertStringSidToSid(sid_str)
                        else:
                            sid, _, _ = win32security.LookupAccountName(None, sid_str)
                        
                        # Add ACE
                        dacl.AddAccessAllowedAce(
                            win32security.ACL_REVISION,
                            access_mask,
                            sid
                        )
                    except Exception as e:
                        logger.warning(f"Failed to add ACE for {sid_str}: {e}")
                
                # Set DACL
                sd.SetSecurityDescriptorDacl(True, dacl, False)
            
            # Apply security descriptor
            win32security.SetFileSecurity(
                str(path),
                win32security.DACL_SECURITY_INFORMATION |
                win32security.OWNER_SECURITY_INFORMATION,
                sd
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to set permissions on {path}: {e}")
            return False
    
    @staticmethod
    def get_file_permissions(path: Path) -> Dict[str, Any]:
        """
        Get file/directory permissions.
        
        Args:
            path: Path to check
            
        Returns:
            Dictionary with permission information
        """
        info = {
            "owner": None,
            "group": None,
            "dacl": [],
            "effective_permissions": {
                "read": False,
                "write": False,
                "execute": False,
                "delete": False
            }
        }
        
        try:
            # Get security descriptor
            sd = win32security.GetFileSecurity(
                str(path),
                win32security.OWNER_SECURITY_INFORMATION |
                win32security.GROUP_SECURITY_INFORMATION |
                win32security.DACL_SECURITY_INFORMATION
            )
            
            # Get owner
            try:
                owner_sid = sd.GetSecurityDescriptorOwner()
                owner_name, owner_domain, _ = win32security.LookupAccountSid(
                    None, owner_sid
                )
                info["owner"] = f"{owner_domain}\\{owner_name}" if owner_domain else owner_name
            except Exception:
                pass
            
            # Get group
            try:
                group_sid = sd.GetSecurityDescriptorGroup()
                if group_sid:
                    group_name, group_domain, _ = win32security.LookupAccountSid(
                        None, group_sid
                    )
                    info["group"] = f"{group_domain}\\{group_name}" if group_domain else group_name
            except Exception:
                pass
            
            # Get DACL entries
            dacl = sd.GetSecurityDescriptorDacl()
            if dacl:
                for i in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(i)
                    ace_type = ace[0][0]
                    ace_flags = ace[0][1]
                    mask = ace[1]
                    sid = ace[2]
                    
                    try:
                        name, domain, _ = win32security.LookupAccountSid(None, sid)
                        principal = f"{domain}\\{name}" if domain else name
                    except Exception:
                        principal = win32security.ConvertSidToStringSid(sid)
                    
                    info["dacl"].append({
                        "principal": principal,
                        "type": "allow" if ace_type == ntsecuritycon.ACCESS_ALLOWED_ACE_TYPE else "deny",
                        "permissions": SecurityUtils._decode_access_mask(mask),
                        "inherited": bool(ace_flags & ntsecuritycon.INHERITED_ACE)
                    })
            
            # Check effective permissions for current user
            if os.access(str(path), os.R_OK):
                info["effective_permissions"]["read"] = True
            if os.access(str(path), os.W_OK):
                info["effective_permissions"]["write"] = True
            if os.access(str(path), os.X_OK):
                info["effective_permissions"]["execute"] = True
                
        except Exception as e:
            logger.error(f"Failed to get permissions for {path}: {e}")
            
        return info
    
    @staticmethod
    def _decode_access_mask(mask: int) -> List[str]:
        """Decode Windows access mask to permission strings."""
        permissions = []
        
        if mask & ntsecuritycon.FILE_GENERIC_READ:
            permissions.append("read")
        if mask & ntsecuritycon.FILE_GENERIC_WRITE:
            permissions.append("write")
        if mask & ntsecuritycon.FILE_GENERIC_EXECUTE:
            permissions.append("execute")
        if mask & ntsecuritycon.DELETE:
            permissions.append("delete")
        if mask & ntsecuritycon.FILE_READ_ATTRIBUTES:
            permissions.append("read_attributes")
        if mask & ntsecuritycon.FILE_WRITE_ATTRIBUTES:
            permissions.append("write_attributes")
        if mask & ntsecuritycon.READ_CONTROL:
            permissions.append("read_permissions")
        if mask & ntsecuritycon.WRITE_DAC:
            permissions.append("change_permissions")
        if mask & ntsecuritycon.WRITE_OWNER:
            permissions.append("take_ownership")
            
        return permissions
    
    @staticmethod
    def check_path_access(
        path: Path,
        required_access: int = win32con.FILE_GENERIC_READ
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if current user has required access to path.
        
        Args:
            path: Path to check
            required_access: Required access mask
            
        Returns:
            Tuple of (has_access, error_message)
        """
        try:
            # Try to open with required access
            handle = win32file.CreateFile(
                str(path),
                required_access,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS if path.is_dir() else 0,
                None
            )
            win32api.CloseHandle(handle)
            return True, None
            
        except pywintypes.error as e:
            error_code = e.winerror
            
            if error_code == 5:  # Access denied
                return False, "Access denied"
            elif error_code == 2:  # File not found
                return False, "Path not found"
            elif error_code == 3:  # Path not found
                return False, "Path not found"
            else:
                return False, f"Windows error {error_code}: {e.strerror}"
                
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def create_restricted_token(
        remove_privileges: Optional[List[str]] = None,
        disable_sids: Optional[List[str]] = None,
        restricted_sids: Optional[List[str]] = None
    ) -> Optional[int]:
        """
        Create a restricted token for sandboxing.
        
        Args:
            remove_privileges: Privileges to remove
            disable_sids: SIDs to disable
            restricted_sids: SIDs to restrict
            
        Returns:
            Handle to restricted token or None on error
        """
        try:
            # Get current process token
            current_token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_DUPLICATE | 
                win32con.TOKEN_QUERY |
                win32con.TOKEN_ASSIGN_PRIMARY
            )
            
            # Convert string SIDs to PySID objects
            disable_sid_objs = []
            if disable_sids:
                for sid_str in disable_sids:
                    try:
                        sid = win32security.ConvertStringSidToSid(sid_str)
                        disable_sid_objs.append(sid)
                    except Exception:
                        pass
            
            restricted_sid_objs = []
            if restricted_sids:
                for sid_str in restricted_sids:
                    try:
                        sid = win32security.ConvertStringSidToSid(sid_str)
                        restricted_sid_objs.append(sid)
                    except Exception:
                        pass
            
            # Create restricted token
            restricted_token = win32security.CreateRestrictedToken(
                current_token,
                disable_sid_objs,
                remove_privileges or [],
                restricted_sid_objs
            )
            
            return restricted_token
            
        except Exception as e:
            logger.error(f"Failed to create restricted token: {e}")
            return None
    
    @staticmethod
    def enable_privilege(privilege_name: str) -> bool:
        """
        Enable a privilege for the current process.
        
        Args:
            privilege_name: Name of privilege (e.g., SeDebugPrivilege)
            
        Returns:
            Success status
        """
        try:
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
            )
            
            luid = win32security.LookupPrivilegeValue(None, privilege_name)
            privilege = [(luid, win32con.SE_PRIVILEGE_ENABLED)]
            
            win32security.AdjustTokenPrivileges(token, False, privilege)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to enable privilege {privilege_name}: {e}")
            return False
    
    @staticmethod
    def validate_path_security(
        path: Path,
        allowed_paths: List[Path],
        check_symlinks: bool = True
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate that a path is within allowed boundaries.
        
        Args:
            path: Path to validate
            allowed_paths: List of allowed parent paths
            check_symlinks: Whether to resolve symlinks
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Resolve path
            if check_symlinks:
                resolved_path = path.resolve()
            else:
                resolved_path = path.absolute()
            
            # Check if path is within allowed paths
            for allowed_path in allowed_paths:
                try:
                    resolved_path.relative_to(allowed_path.resolve())
                    return True, None
                except ValueError:
                    continue
            
            return False, "Path is outside allowed directories"
            
        except Exception as e:
            return False, f"Path validation error: {e}"
    
    @staticmethod
    def sanitize_command(command: str, blocked_patterns: List[str]) -> Tuple[bool, Optional[str]]:
        """
        Check command for potentially dangerous patterns.
        
        Args:
            command: Command to check
            blocked_patterns: List of blocked command patterns
            
        Returns:
            Tuple of (is_safe, matched_pattern)
        """
        command_lower = command.lower()
        
        for pattern in blocked_patterns:
            if pattern.lower() in command_lower:
                return False, pattern
        
        # Check for common dangerous patterns
        dangerous_patterns = [
            ">>",  # Append redirect
            "|",   # Pipe
            "&",   # Command chaining
            "rm -rf",
            "del /s /q",
            "format",
            "diskpart",
        ]
        
        for pattern in dangerous_patterns:
            if pattern in command_lower:
                return False, pattern
        
        return True, None
    
    @staticmethod
    def get_process_integrity_level(pid: int) -> Optional[str]:
        """
        Get integrity level of a process.
        
        Args:
            pid: Process ID
            
        Returns:
            Integrity level string or None
        """
        try:
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
            
            token = win32security.OpenProcessToken(
                process_handle,
                win32con.TOKEN_QUERY
            )
            
            # Get integrity level
            integrity_level = win32security.GetTokenInformation(
                token,
                win32security.TokenIntegrityLevel
            )
            
            # Map RID to level name
            rid = win32security.GetSidSubAuthority(
                integrity_level[0],
                win32security.GetSidSubAuthorityCount(integrity_level[0]) - 1
            )
            
            levels = {
                0x0000: "Untrusted",
                0x1000: "Low",
                0x2000: "Medium",
                0x2100: "Medium Plus",
                0x3000: "High",
                0x4000: "System",
                0x5000: "Protected Process",
            }
            
            return levels.get(rid, f"Unknown ({rid})")
            
        except Exception as e:
            logger.error(f"Failed to get integrity level for PID {pid}: {e}")
            return None


# Convenience functions
def is_admin() -> bool:
    """Check if running with admin privileges."""
    return SecurityUtils.is_admin()


def get_current_user() -> Tuple[str, str]:
    """Get current username and domain."""
    return SecurityUtils.get_current_user()


def check_path_access(path: Path, write: bool = False) -> Tuple[bool, Optional[str]]:
    """Check path access for current user."""
    access_mask = (
        win32con.FILE_GENERIC_WRITE if write 
        else win32con.FILE_GENERIC_READ
    )
    return SecurityUtils.check_path_access(path, access_mask)


def validate_path_security(
    path: Path,
    allowed_paths: List[Path]
) -> Tuple[bool, Optional[str]]:
    """Validate path is within allowed boundaries."""
    return SecurityUtils.validate_path_security(path, allowed_paths)


def sanitize_command(command: str, blocked: List[str]) -> Tuple[bool, Optional[str]]:
    """Check command for dangerous patterns."""
    return SecurityUtils.sanitize_command(command, blocked)