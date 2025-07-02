"""
Base shell abstraction for MCP Windows Development Server.

This module provides the abstract base class for shell implementations
with common functionality for command execution and process management.
"""

import asyncio
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional,Set, Tuple, Union
from datetime import datetime
from dataclasses import dataclass, field
import signal

import structlog

from ..models.command_result import CommandResult, CommandStatus, CommandEnvironment, ShellType
from ..utils.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class ShellProcess:
    """Information about a shell process."""
    
    process: asyncio.subprocess.Process
    shell_type: ShellType
    created_at: datetime = field(default_factory=datetime.utcnow)
    working_directory: Path = field(default_factory=Path.cwd)
    environment: Dict[str, str] = field(default_factory=dict)
    encoding: str = "utf-8"
    
    @property
    def pid(self) -> Optional[int]:
        """Get process ID."""
        return self.process.pid if self.process else None
    
    @property
    def is_alive(self) -> bool:
        """Check if process is still running."""
        return self.process and self.process.returncode is None
    
    async def terminate(self, timeout: float = 5.0) -> None:
        """Terminate the shell process."""
        if not self.is_alive:
            return
        
        try:
            self.process.terminate()
            await asyncio.wait_for(self.process.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            # Force kill if terminate didn't work
            try:
                self.process.kill()
                await self.process.wait()
            except Exception:
                pass


class BaseShell(ABC):
    """
    Abstract base class for shell implementations.
    
    This class provides common functionality for different shell types
    including process management, output handling, and timeout control.
    """
    
    def __init__(
        self,
        shell_type: ShellType,
        executable_path: Optional[Path] = None,
        default_encoding: Optional[str] = None,
        startup_timeout: float = 10.0
    ):
        """
        Initialize base shell.
        
        Args:
            shell_type: Type of shell
            executable_path: Path to shell executable
            default_encoding: Default text encoding
            startup_timeout: Timeout for shell startup
        """
        self.shell_type = shell_type
        self.executable_path = executable_path or self._get_default_executable()
        self.default_encoding = default_encoding or shell_type.default_encoding
        self.startup_timeout = startup_timeout
        
        # Process tracking
        self._processes: Dict[int, ShellProcess] = {}
        self._lock = asyncio.Lock()
        
        logger.debug(
            "Initialized shell",
            type=shell_type.value,
            executable=str(self.executable_path),
            encoding=self.default_encoding
        )
    
    @abstractmethod
    def _get_default_executable(self) -> Path:
        """Get default executable path for this shell type."""
        pass
    
    @abstractmethod
    def _build_command_args(
        self,
        command: str,
        interactive: bool = False
    ) -> List[str]:
        """
        Build command line arguments for shell execution.
        
        Args:
            command: Command to execute
            interactive: Whether to run in interactive mode
            
        Returns:
            List of command arguments
        """
        pass
    
    @abstractmethod
    def _get_startup_commands(self) -> List[str]:
        """
        Get commands to run on shell startup.
        
        Returns:
            List of startup commands
        """
        pass
    
    def is_available(self) -> bool:
        """
        Check if shell is available on the system.
        
        Returns:
            True if shell executable exists
        """
        return self.executable_path.exists()
    
    async def create_process(
        self,
        working_directory: Optional[Path] = None,
        environment: Optional[Dict[str, str]] = None,
        interactive: bool = False
    ) -> ShellProcess:
        """
        Create a new shell process.
        
        Args:
            working_directory: Working directory for shell
            environment: Environment variables
            interactive: Create interactive shell
            
        Returns:
            Shell process information
        """
        if not self.is_available():
            raise RuntimeError(f"Shell not available: {self.shell_type.value}")
        
        # Prepare environment
        env = os.environ.copy()
        if environment:
            env.update(environment)
        
        # Build command
        if interactive:
            args = self._build_command_args("", interactive=True)
        else:
            # Non-interactive shell that stays open
            args = self._build_command_args("", interactive=False)
        
        # Create process
        process = await asyncio.create_subprocess_exec(
            str(self.executable_path),
            *args[1:] if args else [],
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(working_directory) if working_directory else None,
            env=env,
            creationflags=asyncio.subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
        )
        
        # Create shell process info
        shell_process = ShellProcess(
            process=process,
            shell_type=self.shell_type,
            working_directory=working_directory or Path.cwd(),
            environment=environment or {},
            encoding=self.default_encoding
        )
        
        # Track process
        async with self._lock:
            if process.pid:
                self._processes[process.pid] = shell_process
        
        # Run startup commands
        startup_commands = self._get_startup_commands()
        for cmd in startup_commands:
            try:
                await self._send_command(shell_process, cmd)
            except Exception as e:
                logger.warning(
                    "Failed to run startup command",
                    command=cmd,
                    error=str(e)
                )
        
        logger.info(
            "Created shell process",
            type=self.shell_type.value,
            pid=shell_process.pid,
            working_directory=str(working_directory)
        )
        
        return shell_process
    
    async def execute_command(
        self,
        command: str,
        environment: CommandEnvironment,
        timeout: Optional[float] = None,
        shell_process: Optional[ShellProcess] = None
    ) -> CommandResult:
        """
        Execute a command in the shell.
        
        Args:
            command: Command to execute
            environment: Command environment settings
            timeout: Command timeout (overrides environment)
            shell_process: Existing shell process to use
            
        Returns:
            Command execution result
        """
        # Create result object
        result = CommandResult(
            session_id=environment.session_id,
            command=command,
            environment=environment
        )
        
        # Use provided timeout or environment default
        timeout = timeout or environment.timeout_seconds
        
        try:
            # Create process if not provided
            created_process = False
            if not shell_process:
                shell_process = await self.create_process(
                    working_directory=environment.working_directory,
                    environment=environment.environment_variables
                )
                created_process = True
            
            # Mark as running
            result.start_execution(shell_process.pid or 0)
            
            # Execute command
            stdout, stderr = await self._execute_with_timeout(
                shell_process,
                command,
                timeout
            )
            
            # Get exit code
            exit_code = 0  # Default for interactive shells
            if created_process and shell_process.process.returncode is not None:
                exit_code = shell_process.process.returncode
            
            # Complete execution
            result.complete_execution(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr
            )
            
        except asyncio.TimeoutError:
            result.timeout_execution()
            
            # Terminate process if we created it
            if created_process and shell_process:
                await shell_process.terminate()
                
        except asyncio.CancelledError:
            result.cancel_execution("Command execution cancelled")
            
            # Terminate process if we created it
            if created_process and shell_process:
                await shell_process.terminate()
                
            raise
            
        except Exception as e:
            result.error_execution(e)
            
            # Terminate process if we created it
            if created_process and shell_process:
                await shell_process.terminate()
        
        finally:
            # Clean up process if we created it
            if created_process and shell_process:
                async with self._lock:
                    if shell_process.pid in self._processes:
                        del self._processes[shell_process.pid]
        
        return result
    
    async def execute_script(
        self,
        script_path: Path,
        arguments: List[str],
        environment: CommandEnvironment,
        timeout: Optional[float] = None
    ) -> CommandResult:
        """
        Execute a script file.
        
        Args:
            script_path: Path to script file
            arguments: Script arguments
            environment: Command environment
            timeout: Execution timeout
            
        Returns:
            Command execution result
        """
        # Build command based on shell type
        command = self._build_script_command(script_path, arguments)
        
        return await self.execute_command(
            command,
            environment,
            timeout
        )
    
    @abstractmethod
    def _build_script_command(
        self,
        script_path: Path,
        arguments: List[str]
    ) -> str:
        """Build command to execute a script."""
        pass
    
    async def _execute_with_timeout(
        self,
        shell_process: ShellProcess,
        command: str,
        timeout: Optional[float]
    ) -> Tuple[str, str]:
        """
        Execute command with timeout.
        
        Args:
            shell_process: Shell process to use
            command: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr)
        """
        # Send command
        await self._send_command(shell_process, command)
        
        # Read output with timeout
        if timeout:
            stdout, stderr = await asyncio.wait_for(
                self._read_output(shell_process),
                timeout=timeout
            )
        else:
            stdout, stderr = await self._read_output(shell_process)
        
        return stdout, stderr
    
    async def _send_command(
        self,
        shell_process: ShellProcess,
        command: str
    ) -> None:
        """Send command to shell process."""
        if not shell_process.is_alive:
            raise RuntimeError("Shell process is not running")
        
        # Add newline if not present
        if not command.endswith('\n'):
            command += '\n'
        
        # Encode and send
        shell_process.process.stdin.write(
            command.encode(shell_process.encoding)
        )
        await shell_process.process.stdin.drain()
    
    async def _read_output(
        self,
        shell_process: ShellProcess,
        max_size: int = 1024 * 1024  # 1MB
    ) -> Tuple[str, str]:
        """
        Read output from shell process.
        
        Args:
            shell_process: Shell process
            max_size: Maximum output size
            
        Returns:
            Tuple of (stdout, stderr)
        """
        stdout_data = b""
        stderr_data = b""
        
        # Read stdout
        if shell_process.process.stdout:
            try:
                stdout_data = await shell_process.process.stdout.read(max_size)
            except Exception as e:
                logger.warning(f"Failed to read stdout: {e}")
        
        # Read stderr
        if shell_process.process.stderr:
            try:
                stderr_data = await shell_process.process.stderr.read(max_size)
            except Exception as e:
                logger.warning(f"Failed to read stderr: {e}")
        
        # Decode
        stdout = stdout_data.decode(shell_process.encoding, errors='replace')
        stderr = stderr_data.decode(shell_process.encoding, errors='replace')
        
        return stdout, stderr
    
    async def terminate_all_processes(self) -> int:
        """
        Terminate all shell processes.
        
        Returns:
            Number of processes terminated
        """
        async with self._lock:
            terminated = 0
            
            for pid, shell_process in list(self._processes.items()):
                try:
                    await shell_process.terminate()
                    terminated += 1
                except Exception as e:
                    logger.warning(
                        "Failed to terminate shell process",
                        pid=pid,
                        error=str(e)
                    )
                
                del self._processes[pid]
            
            return terminated
    
    def get_active_process_count(self) -> int:
        """Get number of active shell processes."""
        return len(self._processes)
    
    def __str__(self) -> str:
        """String representation."""
        return f"{self.__class__.__name__}({self.shell_type.value})"


class ShellDetector:
    """Detects available shells on the system."""
    
    @staticmethod
    def detect_available_shells() -> Dict[ShellType, Path]:
        """
        Detect which shells are available.
        
        Returns:
            Dictionary mapping shell types to executable paths
        """
        available = {}
        
        # Common shell locations on Windows
        shell_paths = {
            ShellType.CMD: [
                Path("C:/Windows/System32/cmd.exe"),
                Path("C:/Windows/SysWOW64/cmd.exe"),
            ],
            ShellType.POWERSHELL: [
                Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
                Path("C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell.exe"),
            ],
            ShellType.PWSH: [
                Path("C:/Program Files/PowerShell/7/pwsh.exe"),
                Path("C:/Program Files (x86)/PowerShell/7/pwsh.exe"),
                Path.home() / ".dotnet/tools/pwsh.exe",
            ],
            ShellType.WSL: [
                Path("C:/Windows/System32/wsl.exe"),
            ],
            ShellType.GIT_BASH: [
                Path("C:/Program Files/Git/bin/bash.exe"),
                Path("C:/Program Files (x86)/Git/bin/bash.exe"),
            ],
        }
        
        for shell_type, paths in shell_paths.items():
            for path in paths:
                if path.exists():
                    available[shell_type] = path
                    break
        
        return available
    
    @staticmethod
    def get_preferred_shell(
        available: Dict[ShellType, Path],
        allowed: Optional[Set[str]] = None
    ) -> Optional[Tuple[ShellType, Path]]:
        """
        Get preferred shell from available options.
        
        Args:
            available: Available shells
            allowed: Allowed shell types
            
        Returns:
            Tuple of (shell_type, path) or None
        """
        # Preference order
        preference = [
            ShellType.PWSH,  # PowerShell Core
            ShellType.POWERSHELL,  # Windows PowerShell
            ShellType.CMD,  # Command Prompt
            ShellType.GIT_BASH,  # Git Bash
            ShellType.WSL,  # WSL
        ]
        
        for shell_type in preference:
            if shell_type in available:
                if allowed and shell_type.value not in allowed:
                    continue
                return shell_type, available[shell_type]
        
        return None