"""
Security manager for MCP Windows Development Server.

This module provides comprehensive security enforcement including Windows Job Objects,
ACL management, process isolation, and security policy enforcement.
"""

import os
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum
import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field

import win32api
import win32con
import win32job
import win32process
import win32security
import win32file
import pywintypes
import psutil
import structlog

from ..config.settings import SecuritySettings, SecurityMode
from ..models.session import Session, SessionPermissions
from ..models.registry_entry import PermissionLevel
from ..utils.security_utils import SecurityUtils
from ..utils.logging_config import get_security_logger

logger = structlog.get_logger(__name__)
security_logger = get_security_logger()


@dataclass
class JobObjectLimits:
    """Limits for Windows Job Object."""
    
    max_processes: int = 50
    max_memory_mb: int = 2048
    max_cpu_percent: Optional[int] = None
    max_execution_time_seconds: Optional[int] = None
    kill_on_close: bool = True
    breakaway_ok: bool = False
    
    def to_win32_limits(self) -> Dict[str, Any]:
        """Convert to Win32 Job Object limit structures."""
        limits = {}
        
        # Basic limits
        basic_limits = win32job.QueryInformationJobObject(
            None,
            win32job.JobObjectBasicLimitInformation
        )
        
        basic_limits['LimitFlags'] = 0
        
        if self.max_processes:
            basic_limits['ActiveProcessLimit'] = self.max_processes
            basic_limits['LimitFlags'] |= win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        
        if self.kill_on_close:
            basic_limits['LimitFlags'] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        
        if self.breakaway_ok:
            basic_limits['LimitFlags'] |= win32job.JOB_OBJECT_LIMIT_BREAKAWAY_OK
        
        limits['basic'] = basic_limits
        
        # Extended limits (includes memory)
        if self.max_memory_mb or self.max_execution_time_seconds:
            extended_limits = win32job.QueryInformationJobObject(
                None,
                win32job.JobObjectExtendedLimitInformation
            )
            
            if self.max_memory_mb:
                extended_limits['ProcessMemoryLimit'] = self.max_memory_mb * 1024 * 1024
                extended_limits['BasicLimitInformation']['LimitFlags'] |= (
                    win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY
                )
            
            if self.max_execution_time_seconds:
                # Convert seconds to 100-nanosecond intervals
                extended_limits['PerJobUserTimeLimit'] = (
                    self.max_execution_time_seconds * 10000000
                )
                extended_limits['BasicLimitInformation']['LimitFlags'] |= (
                    win32job.JOB_OBJECT_LIMIT_JOB_TIME
                )
            
            limits['extended'] = extended_limits
        
        # CPU rate control (Windows 8+)
        if self.max_cpu_percent:
            cpu_rate = {
                'ControlFlags': win32job.JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
                'CpuRate': self.max_cpu_percent * 100  # In hundredths of a percent
            }
            limits['cpu_rate'] = cpu_rate
        
        return limits


@dataclass
class ProcessInfo:
    """Information about a managed process."""
    
    pid: int
    handle: int
    command: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    session_id: Optional[str] = None
    job_handle: Optional[int] = None
    
    @property
    def is_alive(self) -> bool:
        """Check if process is still running."""
        try:
            return psutil.pid_exists(self.pid)
        except Exception:
            return False


class SecurityManager:
    """
    Manages security enforcement for MCP Windows server.
    
    This class handles:
    - Windows Job Object creation and management
    - Process isolation and sandboxing
    - ACL enforcement on files and directories
    - Security policy validation
    - Resource limit enforcement
    """
    
    def __init__(self, settings: SecuritySettings):
        """
        Initialize security manager.
        
        Args:
            settings: Security configuration settings
        """
        self.settings = settings
        self.security_utils = SecurityUtils()
        
        # Track active job objects
        self._job_objects: Dict[str, int] = {}  # session_id -> job_handle
        self._processes: Dict[int, ProcessInfo] = {}  # pid -> ProcessInfo
        
        # Security state
        self._initialized = False
        self._privilege_level = None
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
        
        logger.info(
            "Security manager initialized",
            mode=settings.mode.value,
            job_objects_enabled=settings.job_objects_enabled
        )
    
    async def initialize(self) -> None:
        """Initialize security manager and check privileges."""
        async with self._lock:
            if self._initialized:
                return
            
            # Check privilege level
            self._privilege_level = self.security_utils.get_privilege_level()
            
            # Log security context
            username, domain = self.security_utils.get_current_user()
            logger.info(
                "Security context initialized",
                user=f"{domain}\\{username}",
                privilege_level=self._privilege_level.name,
                is_admin=self.security_utils.is_admin()
            )
            
            # Warn if not admin and strict mode
            if (self.settings.mode == SecurityMode.STRICT and 
                not self.security_utils.is_admin()):
                logger.warning(
                    "Running in strict mode without admin privileges - "
                    "some security features may be limited"
                )
            
            # Enable required privileges
            if self.security_utils.is_admin():
                self._enable_security_privileges()
            
            self._initialized = True
    
    def _enable_security_privileges(self) -> None:
        """Enable Windows security privileges if admin."""
        privileges = [
            "SeDebugPrivilege",  # Debug programs
            "SeSecurityPrivilege",  # Manage auditing and security log
            "SeBackupPrivilege",  # Bypass file security
            "SeRestorePrivilege",  # Bypass file security for write
            "SeTakeOwnershipPrivilege",  # Take ownership of objects
        ]
        
        for privilege in privileges:
            if self.security_utils.enable_privilege(privilege):
                logger.debug(f"Enabled privilege: {privilege}")
            else:
                logger.debug(f"Failed to enable privilege: {privilege}")
    
    async def create_job_object(
        self,
        session: Session,
        limits: Optional[JobObjectLimits] = None
    ) -> Optional[int]:
        """
        Create Windows Job Object for session.
        
        Args:
            session: Session to create job for
            limits: Job object limits to apply
            
        Returns:
            Job object handle or None on error
        """
        if not self.settings.job_objects_enabled:
            return None
        
        async with self._lock:
            try:
                # Use provided limits or create from session
                if limits is None:
                    limits = JobObjectLimits(
                        max_processes=session.resource_limits.max_processes,
                        max_memory_mb=session.resource_limits.max_memory_mb,
                        max_cpu_percent=session.resource_limits.cpu_limit_percent,
                        max_execution_time_seconds=session.resource_limits.max_execution_time_seconds,
                        kill_on_close=True,
                        breakaway_ok=False
                    )
                
                # Create job object
                job_name = f"MCP_Session_{session.id}"
                job_handle = win32job.CreateJobObject(None, job_name)
                
                # Set basic limits
                limit_info = limits.to_win32_limits()
                
                if 'basic' in limit_info:
                    win32job.SetInformationJobObject(
                        job_handle,
                        win32job.JobObjectBasicLimitInformation,
                        limit_info['basic']
                    )
                
                if 'extended' in limit_info:
                    win32job.SetInformationJobObject(
                        job_handle,
                        win32job.JobObjectExtendedLimitInformation,
                        limit_info['extended']
                    )
                
                # Set UI restrictions if no network access
                if not session.permissions.network_access:
                    ui_limits = win32job.QueryInformationJobObject(
                        job_handle,
                        win32job.JobObjectBasicUIRestrictions
                    )
                    ui_limits['UIRestrictionsClass'] = (
                        win32job.JOB_OBJECT_UILIMIT_EXITWINDOWS |
                        win32job.JOB_OBJECT_UILIMIT_DESKTOP |
                        win32job.JOB_OBJECT_UILIMIT_GLOBALATOMS |
                        win32job.JOB_OBJECT_UILIMIT_HANDLES |
                        win32job.JOB_OBJECT_UILIMIT_READCLIPBOARD |
                        win32job.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
                        win32job.JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                    )
                    win32job.SetInformationJobObject(
                        job_handle,
                        win32job.JobObjectBasicUIRestrictions,
                        ui_limits
                    )
                
                # Track job object
                self._job_objects[str(session.id)] = job_handle
                
                logger.info(
                    "Created job object for session",
                    session_id=str(session.id),
                    max_processes=limits.max_processes,
                    max_memory_mb=limits.max_memory_mb
                )
                
                return job_handle
                
            except pywintypes.error as e:
                logger.error(
                    "Failed to create job object",
                    session_id=str(session.id),
                    error=str(e)
                )
                return None
    
    async def assign_process_to_job(
        self,
        process_handle: int,
        session_id: str
    ) -> bool:
        """
        Assign process to session's job object.
        
        Args:
            process_handle: Process handle
            session_id: Session ID
            
        Returns:
            Success status
        """
        async with self._lock:
            job_handle = self._job_objects.get(session_id)
            if not job_handle:
                return True  # No job object, consider success
            
            try:
                win32job.AssignProcessToJobObject(job_handle, process_handle)
                
                # Get process info
                pid = win32process.GetProcessId(process_handle)
                
                logger.debug(
                    "Assigned process to job object",
                    pid=pid,
                    session_id=session_id
                )
                
                return True
                
            except pywintypes.error as e:
                logger.error(
                    "Failed to assign process to job",
                    error=str(e)
                )
                return False
    
    async def create_restricted_process(
        self,
        command: str,
        session: Session,
        working_directory: Optional[Path] = None,
        environment: Optional[Dict[str, str]] = None
    ) -> Optional[ProcessInfo]:
        """
        Create a process with security restrictions.
        
        Args:
            command: Command to execute
            session: Session context
            working_directory: Working directory
            environment: Environment variables
            
        Returns:
            ProcessInfo or None on error
        """
        try:
            # Validate command
            is_safe, blocked = self.security_utils.sanitize_command(
                command,
                self.settings.blocked_commands
            )
            
            if not is_safe:
                security_logger.log_command_blocked(
                    command,
                    str(session.id),
                    blocked or "unknown"
                )
                
                if self.settings.mode != SecurityMode.PERMISSIVE:
                    raise SecurityViolationError(
                        f"Command blocked: contains '{blocked}'"
                    )
            
            # Create startup info
            startup_info = win32process.STARTUPINFO()
            startup_info.dwFlags = win32process.STARTF_USESHOWWINDOW
            startup_info.wShowWindow = win32con.SW_HIDE
            
            # Security attributes
            security_attributes = win32security.SECURITY_ATTRIBUTES()
            security_attributes.bInheritHandle = False
            
            # Process creation flags
            creation_flags = (
                win32process.CREATE_NEW_CONSOLE |
                win32process.CREATE_NEW_PROCESS_GROUP
            )
            
            # Create restricted token if needed
            token = None
            if self.settings.mode == SecurityMode.PARANOID:
                token = self._create_restricted_token(session)
            
            # Create process
            proc_info = win32process.CreateProcess(
                None,  # Application name
                command,  # Command line
                security_attributes,  # Process attributes
                security_attributes,  # Thread attributes
                False,  # Inherit handles
                creation_flags,  # Creation flags
                environment,  # Environment
                str(working_directory) if working_directory else None,
                startup_info  # Startup info
            )
            
            process_handle, thread_handle, pid, tid = proc_info
            
            # Close thread handle
            win32api.CloseHandle(thread_handle)
            
            # Assign to job object
            if session.job_object_handle:
                await self.assign_process_to_job(process_handle, str(session.id))
            
            # Create process info
            process_info = ProcessInfo(
                pid=pid,
                handle=process_handle,
                command=command[:200],  # Truncate for storage
                session_id=str(session.id),
                job_handle=session.job_object_handle
            )
            
            # Track process
            self._processes[pid] = process_info
            
            logger.info(
                "Created restricted process",
                pid=pid,
                session_id=str(session.id),
                command_truncated=command[:50]
            )
            
            return process_info
            
        except Exception as e:
            logger.error(
                "Failed to create restricted process",
                error=str(e),
                command=command[:50]
            )
            return None
    
    def _create_restricted_token(self, session: Session) -> Optional[int]:
        """Create restricted token for process."""
        # Remove dangerous privileges
        remove_privileges = [
            "SeDebugPrivilege",
            "SeTcbPrivilege",
            "SeCreateTokenPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeManageVolumePrivilege",
        ]
        
        # Disable administrative SIDs
        disable_sids = []
        if not session.permissions.debug_processes:
            disable_sids.append(self.security_utils.ADMINISTRATORS_SID)
        
        return self.security_utils.create_restricted_token(
            remove_privileges=remove_privileges,
            disable_sids=disable_sids
        )
    
    async def validate_path_access(
        self,
        path: Path,
        session: Session,
        required_permission: PermissionLevel,
        operation: str = "access"
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate path access for session.
        
        Args:
            path: Path to validate
            session: Session context
            required_permission: Required permission level
            operation: Operation being performed
            
        Returns:
            Tuple of (allowed, reason_if_not)
        """
        # Normalize path
        path = path.resolve()
        
        # Check if path is within workspace
        try:
            path.relative_to(session.workspace_path)
            workspace_relative = True
        except ValueError:
            workspace_relative = False
        
        # In permissive mode, allow workspace access
        if (self.settings.mode == SecurityMode.PERMISSIVE and
            workspace_relative):
            return True, None
        
        # Check against session permissions
        allowed = False
        reason = None
        
        # Check read-only paths
        for allowed_path in session.permissions.read_only_paths:
            try:
                path.relative_to(allowed_path)
                if required_permission <= PermissionLevel.READ_ONLY:
                    allowed = True
                    break
                else:
                    reason = "Path is read-only"
            except ValueError:
                continue
        
        # Check read-write paths
        if not allowed:
            for allowed_path in session.permissions.read_write_paths:
                try:
                    path.relative_to(allowed_path)
                    if required_permission <= PermissionLevel.READ_WRITE:
                        allowed = True
                        break
                    else:
                        reason = "Path does not allow execution"
                except ValueError:
                    continue
        
        # Check blocked paths
        for blocked_path in session.permissions.blocked_paths:
            try:
                path.relative_to(blocked_path)
                allowed = False
                reason = "Path is explicitly blocked"
                break
            except ValueError:
                continue
        
        # Log access violation if denied
        if not allowed and reason:
            security_logger.log_access_violation(
                path,
                operation,
                session.metadata.owner,
                reason
            )
        
        return allowed, reason
    
    async def set_path_permissions(
        self,
        path: Path,
        session: Session,
        permission_level: PermissionLevel
    ) -> bool:
        """
        Set ACL permissions on path for session.
        
        Args:
            path: Path to secure
            session: Session context
            permission_level: Permission level to set
            
        Returns:
            Success status
        """
        if not self.settings.acl_enforcement:
            return True
        
        try:
            # Get current user SID
            user_sid = win32security.ConvertStringSidToSid(
                self.security_utils.get_current_user_sid()
            )
            
            # Build permission dict
            permissions = {
                self.security_utils.get_current_user_sid(): 
                    permission_level.to_windows_mask()
            }
            
            # Add system access
            permissions[self.security_utils.SYSTEM_SID] = win32con.GENERIC_ALL
            
            # Set permissions
            success = self.security_utils.set_file_permissions(
                path,
                owner_sid=user_sid,
                permissions=permissions,
                inherit=self.settings.inherit_parent_acls
            )
            
            if success:
                logger.debug(
                    "Set path permissions",
                    path=str(path),
                    permission_level=str(permission_level)
                )
            
            return success
            
        except Exception as e:
            logger.error(
                "Failed to set path permissions",
                path=str(path),
                error=str(e)
            )
            return False
    
    async def terminate_session_processes(self, session_id: str) -> int:
        """
        Terminate all processes in a session.
        
        Args:
            session_id: Session ID
            
        Returns:
            Number of processes terminated
        """
        async with self._lock:
            terminated = 0
            
            # Use job object if available
            job_handle = self._job_objects.get(session_id)
            if job_handle:
                try:
                    win32job.TerminateJobObject(job_handle, 1)
                    
                    # Count terminated processes
                    for pid, info in list(self._processes.items()):
                        if info.session_id == session_id:
                            del self._processes[pid]
                            terminated += 1
                    
                    logger.info(
                        "Terminated job object processes",
                        session_id=session_id,
                        count=terminated
                    )
                    
                except Exception as e:
                    logger.error(
                        "Failed to terminate job object",
                        session_id=session_id,
                        error=str(e)
                    )
            
            # Terminate individual processes
            else:
                for pid, info in list(self._processes.items()):
                    if info.session_id == session_id:
                        try:
                            proc = psutil.Process(pid)
                            proc.terminate()
                            proc.wait(timeout=5)
                            terminated += 1
                        except Exception:
                            # Try force kill
                            try:
                                proc = psutil.Process(pid)
                                proc.kill()
                                terminated += 1
                            except Exception:
                                pass
                        
                        del self._processes[pid]
            
            return terminated
    
    async def cleanup_job_object(self, session_id: str) -> None:
        """
        Clean up job object for session.
        
        Args:
            session_id: Session ID
        """
        async with self._lock:
            job_handle = self._job_objects.get(session_id)
            if job_handle:
                try:
                    win32api.CloseHandle(job_handle)
                    del self._job_objects[session_id]
                    
                    logger.debug(
                        "Cleaned up job object",
                        session_id=session_id
                    )
                except Exception as e:
                    logger.error(
                        "Failed to cleanup job object",
                        session_id=session_id,
                        error=str(e)
                    )
    
    async def get_session_resource_usage(
        self,
        session_id: str
    ) -> Dict[str, float]:
        """
        Get resource usage for session.
        
        Args:
            session_id: Session ID
            
        Returns:
            Resource usage metrics
        """
        usage = {
            "cpu_percent": 0.0,
            "memory_mb": 0.0,
            "process_count": 0,
            "thread_count": 0,
        }
        
        # Get processes for session
        session_pids = [
            pid for pid, info in self._processes.items()
            if info.session_id == session_id
        ]
        
        for pid in session_pids:
            try:
                proc = psutil.Process(pid)
                with proc.oneshot():
                    usage["cpu_percent"] += proc.cpu_percent()
                    usage["memory_mb"] += proc.memory_info().rss / (1024 * 1024)
                    usage["process_count"] += 1
                    usage["thread_count"] += proc.num_threads()
            except Exception:
                pass
        
        return usage
    
    async def validate_command_execution(
        self,
        command: str,
        session: Session
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate command execution is allowed.
        
        Args:
            command: Command to validate
            session: Session context
            
        Returns:
            Tuple of (allowed, reason_if_not)
        """
        # Check blocked commands
        is_safe, pattern = self.security_utils.sanitize_command(
            command,
            self.settings.blocked_commands
        )
        
        if not is_safe:
            return False, f"Command matches blocked pattern: {pattern}"
        
        # Extract executable
        parts = command.split()
        if not parts:
            return False, "Empty command"
        
        executable = parts[0].lower()
        
        # Check shell restrictions
        shell_commands = {
            "cmd", "cmd.exe", 
            "powershell", "powershell.exe",
            "pwsh", "pwsh.exe",
            "bash", "bash.exe",
            "wsl", "wsl.exe"
        }
        
        if executable in shell_commands:
            shell_type = executable.split('.')[0]
            if shell_type not in session.permissions.allowed_shells:
                return False, f"Shell type '{shell_type}' not allowed"
        
        # Check executable extension
        if '.' in executable:
            ext = '.' + executable.split('.')[-1]
            if ext not in self.settings.allowed_extensions:
                return False, f"Executable extension '{ext}' not allowed"
        
        return True, None
    
    async def monitor_security_health(self) -> Dict[str, Any]:
        """
        Get security health metrics.
        
        Returns:
            Security health information
        """
        health = {
            "initialized": self._initialized,
            "privilege_level": self._privilege_level.name if self._privilege_level else "unknown",
            "mode": self.settings.mode.value,
            "active_job_objects": len(self._job_objects),
            "monitored_processes": len(self._processes),
            "acl_enforcement": self.settings.acl_enforcement,
            "job_objects_enabled": self.settings.job_objects_enabled,
        }
        
        # Check for orphaned processes
        orphaned = 0
        for pid, info in list(self._processes.items()):
            if not info.is_alive:
                orphaned += 1
                del self._processes[pid]
        
        health["orphaned_processes_cleaned"] = orphaned
        
        return health


class SecurityViolationError(Exception):
    """Raised when security policy is violated."""
    pass