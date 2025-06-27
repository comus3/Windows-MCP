"""
Command executor for MCP Windows Development Server.

This module provides the main command execution engine that handles
multi-shell execution, process management, and result aggregation.
"""

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from datetime import datetime
from uuid import UUID
import psutil

import structlog

from ..config.settings import MCPWindowsSettings, SecuritySettings
from ..models.session import Session
from ..models.command_result import (
    CommandResult, CommandStatus, CommandEnvironment,
    ShellType, CommandBatch, CommandMetrics
)
from ..shells.base_shell import BaseShell, ShellDetector
from ..shells.cmd_shell import CmdShell
from ..shells.powershell_shell import PowerShellShell, PwshShell, create_powershell_shell
from ..utils.logging_config import get_logger, AuditLogger, PerformanceLogger

logger = get_logger(__name__)


class ShellFactory:
    """Factory for creating shell instances."""
    
    def __init__(self, settings: MCPWindowsSettings):
        """
        Initialize shell factory.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self._shell_cache: Dict[ShellType, BaseShell] = {}
    
    def create_shell(self, shell_type: ShellType) -> BaseShell:
        """
        Create or get cached shell instance.
        
        Args:
            shell_type: Type of shell
            
        Returns:
            Shell instance
            
        Raises:
            ValueError: If shell type not supported
        """
        # Check cache
        if shell_type in self._shell_cache:
            return self._shell_cache[shell_type]
        
        # Create new instance
        if shell_type == ShellType.CMD:
            if not self.settings.shell.cmd_enabled:
                raise ValueError("CMD shell is disabled")
            shell = CmdShell(self.settings.shell)
            
        elif shell_type in (ShellType.POWERSHELL, ShellType.PWSH):
            if shell_type == ShellType.POWERSHELL and not self.settings.shell.powershell_enabled:
                raise ValueError("PowerShell is disabled")
            elif shell_type == ShellType.PWSH and not self.settings.shell.pwsh_enabled:
                raise ValueError("PowerShell Core is disabled")
            shell = create_powershell_shell(shell_type, self.settings.shell)
            
        else:
            raise ValueError(f"Unsupported shell type: {shell_type}")
        
        # Verify availability
        if not shell.is_available():
            raise RuntimeError(f"Shell not available: {shell_type.value}")
        
        # Cache instance
        self._shell_cache[shell_type] = shell
        
        return shell
    
    def get_available_shells(self) -> Dict[ShellType, BaseShell]:
        """
        Get all available shell instances.
        
        Returns:
            Dictionary of available shells
        """
        available = {}
        
        for shell_type in ShellType:
            try:
                shell = self.create_shell(shell_type)
                if shell.is_available():
                    available[shell_type] = shell
            except Exception:
                pass
        
        return available
    
    async def cleanup(self) -> None:
        """Clean up all shell instances."""
        for shell in self._shell_cache.values():
            try:
                await shell.terminate_all_processes()
            except Exception as e:
                logger.error(
                    "Failed to cleanup shell",
                    shell_type=shell.shell_type.value,
                    error=str(e)
                )
        
        self._shell_cache.clear()


class CommandExecutor:
    """
    Main command execution engine.
    
    This class handles:
    - Command execution across different shells
    - Process lifecycle management
    - Resource monitoring and limits
    - Result aggregation and reporting
    """
    
    def __init__(
        self,
        settings: MCPWindowsSettings,
        security_manager=None,
        session_manager=None
    ):
        """
        Initialize command executor.
        
        Args:
            settings: Application settings
            security_manager: Security manager instance
            session_manager: Session manager instance
        """
        self.settings = settings
        self.security_manager = security_manager
        self.session_manager = session_manager
        
        # Shell management
        self._shell_factory = ShellFactory(settings)
        self._active_commands: Dict[UUID, CommandResult] = {}
        
        # Auditing and performance
        self._audit_logger = AuditLogger(
            settings.workspace.root_directory / ".audit" / "commands.log"
        )
        self._performance_logger = PerformanceLogger()
        
        # Concurrency control
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_commands)
        self._lock = asyncio.Lock()
        
        logger.info(
            "Command executor initialized",
            max_concurrent=settings.max_concurrent_commands
        )
    
    async def execute_command(
        self,
        command: str,
        session_id: UUID,
        shell_type: Optional[ShellType] = None,
        working_directory: Optional[Path] = None,
        environment_variables: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> CommandResult:
        """
        Execute a command in a session.
        
        Args:
            command: Command to execute
            session_id: Session ID
            shell_type: Shell to use (auto-detect if None)
            working_directory: Working directory
            environment_variables: Additional environment variables
            timeout: Command timeout
            
        Returns:
            Command execution result
        """
        # Get session
        if not self.session_manager:
            raise RuntimeError("Session manager not available")
        
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")
        
        # Validate command if security manager available
        if self.security_manager:
            allowed, reason = await self.security_manager.validate_command_execution(
                command, session
            )
            if not allowed:
                # Create failed result
                result = CommandResult(
                    session_id=session_id,
                    command=command,
                    environment=CommandEnvironment(
                        working_directory=working_directory or session.workspace_path,
                        shell_type=shell_type or ShellType.CMD,
                        timeout_seconds=timeout
                    ),
                    status=CommandStatus.FAILED,
                    error_message=f"Command blocked: {reason}"
                )
                return result
        
        # Determine shell type
        if not shell_type:
            shell_type = self._auto_detect_shell(command, session)
        
        # Validate shell allowed
        if shell_type.value not in session.permissions.allowed_shells:
            raise ValueError(f"Shell type not allowed: {shell_type.value}")
        
        # Create command environment
        env = CommandEnvironment(
            working_directory=working_directory or session.workspace_path,
            environment_variables=environment_variables or {},
            shell_type=shell_type,
            timeout_seconds=timeout or self.settings.security.command_timeout_seconds
        )
        
        # Execute with concurrency control
        async with self._semaphore:
            return await self._execute_command_internal(
                command, session, env
            )
    
    async def execute_batch_commands(
        self,
        commands: List[str],
        session_id: UUID,
        shell_type: Optional[ShellType] = None,
        stop_on_error: bool = True,
        parallel: bool = False
    ) -> CommandBatch:
        """
        Execute multiple commands.
        
        Args:
            commands: Commands to execute
            session_id: Session ID
            shell_type: Shell to use
            stop_on_error: Stop on first error
            parallel: Execute in parallel
            
        Returns:
            Batch execution results
        """
        # Get session
        if not self.session_manager:
            raise RuntimeError("Session manager not available")
        
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")
        
        # Create batch result
        batch = CommandBatch(
            session_id=session_id,
            results=[],
            stop_on_error=stop_on_error,
            parallel=parallel
        )
        
        if parallel:
            # Execute in parallel
            tasks = [
                self.execute_command(cmd, session_id, shell_type)
                for cmd in commands
            ]
            
            # Use gather to handle exceptions
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    # Create error result
                    error_result = CommandResult(
                        session_id=session_id,
                        command=commands[i],
                        environment=CommandEnvironment(
                            working_directory=session.workspace_path,
                            shell_type=shell_type or ShellType.CMD
                        )
                    )
                    error_result.error_execution(result)
                    batch.results.append(error_result)
                else:
                    batch.results.append(result)
        else:
            # Execute sequentially
            for command in commands:
                result = await self.execute_command(
                    command, session_id, shell_type
                )
                batch.results.append(result)
                
                # Check if should stop
                if stop_on_error and not result.is_success:
                    break
        
        return batch
    
    async def _execute_command_internal(
        self,
        command: str,
        session: Session,
        environment: CommandEnvironment
    ) -> CommandResult:
        """Internal command execution."""
        # Create result
        result = CommandResult(
            session_id=session.id,
            command=command,
            environment=environment
        )
        
        # Track active command
        async with self._lock:
            self._active_commands[result.id] = result
        
        # Measure performance
        start_time = datetime.utcnow()
        start_memory = psutil.Process().memory_info().rss
        
        try:
            # Get shell
            shell = self._shell_factory.create_shell(environment.shell_type)
            
            # Execute with security manager if available
            if self.security_manager:
                # Create restricted process
                process_info = await self.security_manager.create_restricted_process(
                    command,
                    session,
                    environment.working_directory,
                    environment.environment_variables
                )
                
                if not process_info:
                    raise RuntimeError("Failed to create process")
                
                # Update result with process info
                result.process_id = process_info.pid
                
                # Wait for completion with timeout
                try:
                    exit_code = await asyncio.wait_for(
                        process_info.process.wait(),
                        timeout=environment.timeout_seconds
                    )
                    
                    # Read output
                    stdout, stderr = await process_info.process.communicate()
                    
                    # Complete result
                    result.complete_execution(
                        exit_code=exit_code,
                        stdout=stdout.decode(environment.encoding or "utf-8", errors="replace"),
                        stderr=stderr.decode(environment.encoding or "utf-8", errors="replace")
                    )
                    
                except asyncio.TimeoutError:
                    result.timeout_execution()
                    # Terminate process
                    try:
                        process_info.process.terminate()
                        await asyncio.wait_for(process_info.process.wait(), timeout=5)
                    except:
                        process_info.process.kill()
                        
            else:
                # Execute without security restrictions
                result = await shell.execute_command(
                    command,
                    environment,
                    timeout=environment.timeout_seconds
                )
            
            # Collect metrics
            end_time = datetime.utcnow()
            end_memory = psutil.Process().memory_info().rss
            
            metrics = CommandMetrics(
                cpu_time_seconds=(end_time - start_time).total_seconds(),
                peak_memory_mb=(end_memory - start_memory) / (1024 * 1024),
                process_count=1
            )
            result.metrics = metrics
            
            # Log performance
            self._performance_logger.log_command_performance(
                str(result.id),
                result.duration_seconds * 1000 if result.duration_seconds else 0,
                result.exit_code or -1,
                metrics.peak_memory_mb
            )
            
        except Exception as e:
            logger.error(
                "Command execution failed",
                command_id=str(result.id),
                error=str(e)
            )
            result.error_execution(e)
        
        finally:
            # Remove from active commands
            async with self._lock:
                self._active_commands.pop(result.id, None)
            
            # Audit log
            self._audit_logger.log_command_executed(
                str(session.id),
                command,
                result.exit_code or -1,
                result.duration_seconds or 0
            )
            
            # Update session
            session.add_process(result.process_id or 0)
            if result.is_complete:
                session.remove_process(result.process_id or 0)
        
        return result
    
    def _auto_detect_shell(self, command: str, session: Session) -> ShellType:
        """Auto-detect appropriate shell for command."""
        command_lower = command.lower()
        
        # PowerShell indicators
        ps_indicators = [
            "get-", "set-", "new-", "remove-", "invoke-",
            "$", "where-object", "select-object", "|", "foreach"
        ]
        
        if any(indicator in command_lower for indicator in ps_indicators):
            # Prefer PowerShell Core if available
            if ShellType.PWSH.value in session.permissions.allowed_shells:
                try:
                    shell = self._shell_factory.create_shell(ShellType.PWSH)
                    if shell.is_available():
                        return ShellType.PWSH
                except:
                    pass
            
            if ShellType.POWERSHELL.value in session.permissions.allowed_shells:
                return ShellType.POWERSHELL
        
        # Default to CMD
        return ShellType.CMD
    
    async def get_active_commands(self) -> List[CommandResult]:
        """Get currently executing commands."""
        async with self._lock:
            return list(self._active_commands.values())
    
    async def cancel_command(self, command_id: UUID) -> bool:
        """
        Cancel an executing command.
        
        Args:
            command_id: Command ID to cancel
            
        Returns:
            Success status
        """
        async with self._lock:
            result = self._active_commands.get(command_id)
            
            if not result:
                return False
            
            # Cancel the command
            result.cancel_execution("Cancelled by user")
            
            # Terminate process if we have security manager
            if self.security_manager and result.process_id:
                try:
                    proc = psutil.Process(result.process_id)
                    proc.terminate()
                    # Give it time to terminate
                    await asyncio.sleep(0.5)
                    if proc.is_running():
                        proc.kill()
                except:
                    pass
            
            return True
    
    async def get_command_metrics(self) -> Dict[str, Any]:
        """Get command execution metrics."""
        return {
            "active_commands": len(self._active_commands),
            "available_shells": list(self._shell_factory.get_available_shells().keys()),
            "max_concurrent": self.settings.max_concurrent_commands,
            "timeout_seconds": self.settings.security.command_timeout_seconds,
        }
    
    async def cleanup(self) -> None:
        """Clean up command executor."""
        # Cancel all active commands
        for command_id in list(self._active_commands.keys()):
            await self.cancel_command(command_id)
        
        # Clean up shells
        await self._shell_factory.cleanup()
        
        logger.info("Command executor cleanup complete")