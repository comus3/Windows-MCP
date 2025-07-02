"""
CMD shell implementation for MCP Windows Development Server.

This module provides the Windows Command Prompt (cmd.exe) shell implementation
with CMD-specific command handling and execution.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional
import asyncio

import structlog

from .base_shell import BaseShell, ShellProcess
from ..models.command_result import CommandResult, CommandEnvironment, ShellType
from ..config.settings import ShellSettings

logger = structlog.get_logger(__name__)


class CmdShell(BaseShell):
    """
    Windows Command Prompt (cmd.exe) shell implementation.
    
    This class provides CMD-specific functionality including:
    - Command prompt customization
    - Batch file execution
    - Environment variable handling
    - CMD extensions support
    """
    
    def __init__(
        self,
        settings: Optional[ShellSettings] = None,
        executable_path: Optional[Path] = None
    ):
        """
        Initialize CMD shell.
        
        Args:
            settings: Shell configuration settings
            executable_path: Override path to cmd.exe
        """
        self.settings = settings or ShellSettings()
        
        # Determine executable path
        if executable_path:
            cmd_path = executable_path
        elif self.settings.cmd_path:
            cmd_path = self.settings.cmd_path
        else:
            cmd_path = self._get_default_executable()
        
        # Initialize base class
        super().__init__(
            shell_type=ShellType.CMD,
            executable_path=cmd_path,
            default_encoding=self.settings.cmd_encoding,
            startup_timeout=self.settings.shell_startup_timeout
        )
        
        # CMD-specific settings
        self.enable_extensions = self.settings.cmd_extensions
        
        logger.info(
            "CMD shell initialized",
            executable=str(self.executable_path),
            encoding=self.default_encoding,
            extensions=self.enable_extensions
        )
    
    def _get_default_executable(self) -> Path:
        """Get default cmd.exe path."""
        # Try standard locations
        standard_paths = [
            Path("C:/Windows/System32/cmd.exe"),
            Path("C:/Windows/SysWOW64/cmd.exe"),
        ]
        
        for path in standard_paths:
            if path.exists():
                return path
        
        # Fall back to environment
        system_root = os.environ.get("SystemRoot", "C:\\Windows")
        return Path(system_root) / "System32" / "cmd.exe"
    
    def _build_command_args(
        self,
        command: str,
        interactive: bool = False
    ) -> List[str]:
        """
        Build CMD command line arguments.
        
        Args:
            command: Command to execute
            interactive: Whether to run in interactive mode
            
        Returns:
            List of command arguments
        """
        args = [str(self.executable_path)]
        
        # Enable extensions if configured
        if self.enable_extensions:
            args.append("/E:ON")
        else:
            args.append("/E:OFF")
        
        # Enable delayed expansion
        args.append("/V:ON")
        
        # Set UTF-8 code page if using UTF-8 encoding
        if self.default_encoding.lower() in ["utf-8", "utf8"]:
            args.extend(["/K", "chcp 65001 >nul"])
        
        if interactive:
            # Interactive mode - stay open
            args.append("/K")
        else:
            # Non-interactive - execute and exit
            args.append("/C")
        
        if command:
            args.append(command)
        
        return args
    
    def _get_startup_commands(self) -> List[str]:
        """Get CMD startup commands."""
        commands = []
        
        # Set prompt
        commands.append("prompt $P$G")
        
        # Echo off for cleaner output
        commands.append("@echo off")
        
        # Set UTF-8 if needed
        if self.default_encoding.lower() in ["utf-8", "utf8"]:
            commands.append("chcp 65001 >nul")
        
        return commands
    
    def _build_script_command(
        self,
        script_path: Path,
        arguments: List[str]
    ) -> str:
        """Build command to execute a batch script."""
        # Quote script path if it contains spaces
        script_str = str(script_path)
        if " " in script_str:
            script_str = f'"{script_str}"'
        
        # Build command with arguments
        cmd_parts = [script_str]
        
        for arg in arguments:
            # Quote arguments containing spaces
            if " " in arg:
                cmd_parts.append(f'"{arg}"')
            else:
                cmd_parts.append(arg)
        
        return " ".join(cmd_parts)
    
    async def execute_batch_file(
        self,
        batch_path: Path,
        arguments: List[str],
        environment: CommandEnvironment,
        timeout: Optional[float] = None
    ) -> CommandResult:
        """
        Execute a batch file.
        
        Args:
            batch_path: Path to .bat or .cmd file
            arguments: Batch file arguments
            environment: Command environment
            timeout: Execution timeout
            
        Returns:
            Command execution result
        """
        if not batch_path.exists():
            raise FileNotFoundError(f"Batch file not found: {batch_path}")
        
        if batch_path.suffix.lower() not in [".bat", ".cmd"]:
            raise ValueError(f"Not a batch file: {batch_path}")
        
        # Use base class script execution
        return await self.execute_script(
            batch_path,
            arguments,
            environment,
            timeout
        )
    
    async def execute_command_with_redirect(
        self,
        command: str,
        environment: CommandEnvironment,
        stdout_file: Optional[Path] = None,
        stderr_file: Optional[Path] = None,
        append: bool = False
    ) -> CommandResult:
        """
        Execute command with output redirection.
        
        Args:
            command: Command to execute
            environment: Command environment
            stdout_file: File to redirect stdout to
            stderr_file: File to redirect stderr to
            append: Append to files instead of overwrite
            
        Returns:
            Command execution result
        """
        # Build redirected command
        redirect_op = ">>" if append else ">"
        
        if stdout_file and stderr_file:
            if stdout_file == stderr_file:
                # Redirect both to same file
                redirected_cmd = f"{command} {redirect_op} \"{stdout_file}\" 2>&1"
            else:
                # Redirect to separate files
                redirected_cmd = f"{command} {redirect_op} \"{stdout_file}\" 2{redirect_op} \"{stderr_file}\""
        elif stdout_file:
            redirected_cmd = f"{command} {redirect_op} \"{stdout_file}\""
        elif stderr_file:
            redirected_cmd = f"{command} 2{redirect_op} \"{stderr_file}\""
        else:
            redirected_cmd = command
        
        # Execute redirected command
        result = await self.execute_command(
            redirected_cmd,
            environment
        )
        
        # Read output from files if redirected
        if stdout_file and stdout_file.exists():
            try:
                result.stdout = stdout_file.read_text(encoding=self.default_encoding)
            except Exception as e:
                logger.warning(f"Failed to read stdout file: {e}")
        
        if stderr_file and stderr_file != stdout_file and stderr_file.exists():
            try:
                result.stderr = stderr_file.read_text(encoding=self.default_encoding)
            except Exception as e:
                logger.warning(f"Failed to read stderr file: {e}")
        
        return result
    
    async def execute_piped_commands(
        self,
        commands: List[str],
        environment: CommandEnvironment,
        timeout: Optional[float] = None
    ) -> CommandResult:
        """
        Execute piped commands.
        
        Args:
            commands: List of commands to pipe
            environment: Command environment
            timeout: Execution timeout
            
        Returns:
            Command execution result
        """
        if not commands:
            raise ValueError("No commands provided")
        
        # Build piped command
        piped_command = " | ".join(commands)
        
        return await self.execute_command(
            piped_command,
            environment,
            timeout
        )
    
    async def set_environment_variable(
        self,
        shell_process: ShellProcess,
        name: str,
        value: str,
        persist: bool = False
    ) -> bool:
        """
        Set environment variable in CMD session.
        
        Args:
            shell_process: Shell process
            name: Variable name
            value: Variable value
            persist: Persist across sessions (requires admin)
            
        Returns:
            Success status
        """
        try:
            if persist:
                # Use setx for persistent variables
                command = f'setx {name} "{value}"'
            else:
                # Use set for session variables
                command = f'set {name}={value}'
            
            await self._send_command(shell_process, command)
            
            # Update process environment tracking
            shell_process.environment[name] = value
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to set environment variable",
                name=name,
                error=str(e)
            )
            return False
    
    async def get_environment_variable(
        self,
        shell_process: ShellProcess,
        name: str
    ) -> Optional[str]:
        """
        Get environment variable value.
        
        Args:
            shell_process: Shell process
            name: Variable name
            
        Returns:
            Variable value or None
        """
        try:
            # Use echo to get variable value
            command = f"echo %{name}%"
            
            await self._send_command(shell_process, command)
            stdout, _ = await self._read_output(shell_process)
            
            # Parse output
            value = stdout.strip()
            
            # Check if variable exists (echo returns %name% if not set)
            if value == f"%{name}%":
                return None
            
            return value
            
        except Exception as e:
            logger.error(
                "Failed to get environment variable",
                name=name,
                error=str(e)
            )
            return None
    
    async def change_directory(
        self,
        shell_process: ShellProcess,
        directory: Path
    ) -> bool:
        """
        Change working directory in shell.
        
        Args:
            shell_process: Shell process
            directory: Target directory
            
        Returns:
            Success status
        """
        try:
            # Use cd command
            command = f'cd /d "{directory}"'
            
            await self._send_command(shell_process, command)
            
            # Update process working directory
            shell_process.working_directory = directory
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to change directory",
                directory=str(directory),
                error=str(e)
            )
            return False
    
    def escape_argument(self, argument: str) -> str:
        """
        Escape argument for CMD.
        
        Args:
            argument: Argument to escape
            
        Returns:
            Escaped argument
        """
        # Characters that need escaping in CMD
        special_chars = ['&', '|', '<', '>', '^', '"']
        
        escaped = argument
        for char in special_chars:
            escaped = escaped.replace(char, f'^{char}')
        
        # Quote if contains spaces
        if ' ' in escaped:
            escaped = f'"{escaped}"'
        
        return escaped
    
    def build_command_line(
        self,
        executable: str,
        arguments: List[str]
    ) -> str:
        """
        Build properly escaped command line.
        
        Args:
            executable: Executable path or name
            arguments: Command arguments
            
        Returns:
            Escaped command line
        """
        # Escape executable if needed
        if ' ' in executable and not (executable.startswith('"') and executable.endswith('"')):
            executable = f'"{executable}"'
        
        # Escape arguments
        escaped_args = [self.escape_argument(arg) for arg in arguments]
        
        # Build command line
        return f"{executable} {' '.join(escaped_args)}" if escaped_args else executable