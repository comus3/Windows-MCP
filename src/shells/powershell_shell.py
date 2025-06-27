"""
PowerShell implementation for MCP Windows Development Server.

This module provides PowerShell and PowerShell Core shell implementations
with PowerShell-specific command handling and execution.
"""

import os
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import asyncio

import structlog

from .base_shell import BaseShell, ShellProcess
from ..models.command_result import CommandResult, CommandEnvironment, ShellType
from ..config.settings import ShellSettings

logger = structlog.get_logger(__name__)


class PowerShellBase(BaseShell):
    """Base class for PowerShell implementations."""
    
    def __init__(
        self,
        shell_type: ShellType,
        settings: Optional[ShellSettings] = None,
        executable_path: Optional[Path] = None,
        execution_policy: Optional[str] = None
    ):
        """
        Initialize PowerShell base.
        
        Args:
            shell_type: Type of PowerShell (POWERSHELL or PWSH)
            settings: Shell configuration settings
            executable_path: Override path to PowerShell
            execution_policy: Execution policy to use
        """
        self.settings = settings or ShellSettings()
        
        # Determine execution policy
        if shell_type == ShellType.POWERSHELL:
            self.execution_policy = execution_policy or self.settings.powershell_execution_policy
        else:
            self.execution_policy = execution_policy or self.settings.pwsh_execution_policy
        
        # Initialize base class
        super().__init__(
            shell_type=shell_type,
            executable_path=executable_path,
            default_encoding="utf-8",  # PowerShell uses UTF-8
            startup_timeout=self.settings.shell_startup_timeout
        )
        
        logger.info(
            f"{shell_type.value} initialized",
            executable=str(self.executable_path),
            execution_policy=self.execution_policy
        )
    
    def _build_command_args(
        self,
        command: str,
        interactive: bool = False
    ) -> List[str]:
        """Build PowerShell command line arguments."""
        args = [str(self.executable_path)]
        
        # Set execution policy
        args.extend(["-ExecutionPolicy", self.execution_policy])
        
        # No profile for cleaner environment
        args.append("-NoProfile")
        
        if interactive:
            # Interactive mode
            args.append("-NoExit")
        else:
            # Non-interactive mode
            if command:
                # Execute command
                args.extend(["-Command", command])
            else:
                # Just start shell
                args.append("-NoExit")
        
        return args
    
    def _get_startup_commands(self) -> List[str]:
        """Get PowerShell startup commands."""
        commands = []
        
        # Set strict mode for better error handling
        commands.append("Set-StrictMode -Version Latest")
        
        # Set error action preference
        commands.append("$ErrorActionPreference = 'Stop'")
        
        # Set output encoding
        commands.append("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8")
        
        # Customize prompt
        commands.append(
            'function prompt { "PS " + (Get-Location).Path + "> " }'
        )
        
        return commands
    
    def _build_script_command(
        self,
        script_path: Path,
        arguments: List[str]
    ) -> str:
        """Build command to execute a PowerShell script."""
        # Build script invocation
        script_str = str(script_path)
        
        # Build arguments
        if arguments:
            # Escape arguments
            escaped_args = []
            for arg in arguments:
                if ' ' in arg or '"' in arg:
                    # Escape quotes and wrap in quotes
                    escaped = arg.replace('"', '`"')
                    escaped_args.append(f'"{escaped}"')
                else:
                    escaped_args.append(arg)
            
            return f"& '{script_str}' {' '.join(escaped_args)}"
        else:
            return f"& '{script_str}'"
    
    async def execute_script_block(
        self,
        script_block: str,
        environment: CommandEnvironment,
        parameters: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None
    ) -> CommandResult:
        """
        Execute a PowerShell script block.
        
        Args:
            script_block: PowerShell script block code
            environment: Command environment
            parameters: Parameters to pass to script block
            timeout: Execution timeout
            
        Returns:
            Command execution result
        """
        # Build script block command
        if parameters:
            # Create parameter string
            param_parts = []
            for name, value in parameters.items():
                if isinstance(value, str):
                    param_parts.append(f"-{name} '{value}'")
                elif isinstance(value, bool):
                    param_parts.append(f"-{name}:${str(value).lower()}")
                else:
                    param_parts.append(f"-{name} {value}")
            
            command = f"& {{{script_block}}} {' '.join(param_parts)}"
        else:
            command = f"& {{{script_block}}}"
        
        return await self.execute_command(
            command,
            environment,
            timeout
        )
    
    async def invoke_cmdlet(
        self,
        cmdlet: str,
        parameters: Optional[Dict[str, Any]] = None,
        environment: CommandEnvironment,
        timeout: Optional[float] = None
    ) -> CommandResult:
        """
        Invoke a PowerShell cmdlet.
        
        Args:
            cmdlet: Cmdlet name
            parameters: Cmdlet parameters
            environment: Command environment
            timeout: Execution timeout
            
        Returns:
            Command execution result
        """
        # Build cmdlet command
        cmd_parts = [cmdlet]
        
        if parameters:
            for name, value in parameters.items():
                if value is None:
                    continue
                elif isinstance(value, bool):
                    if value:
                        cmd_parts.append(f"-{name}")
                elif isinstance(value, str):
                    # Escape quotes
                    escaped = value.replace('"', '`"')
                    cmd_parts.append(f'-{name} "{escaped}"')
                elif isinstance(value, (list, tuple)):
                    # Array parameter
                    array_str = ",".join(f'"{v}"' if isinstance(v, str) else str(v) for v in value)
                    cmd_parts.append(f"-{name} @({array_str})")
                else:
                    cmd_parts.append(f"-{name} {value}")
        
        command = " ".join(cmd_parts)
        
        return await self.execute_command(
            command,
            environment,
            timeout
        )
    
    async def get_variable(
        self,
        shell_process: ShellProcess,
        variable_name: str,
        as_json: bool = False
    ) -> Optional[Union[str, Any]]:
        """
        Get PowerShell variable value.
        
        Args:
            shell_process: Shell process
            variable_name: Variable name (without $)
            as_json: Return as parsed JSON
            
        Returns:
            Variable value or None
        """
        try:
            if as_json:
                command = f"${variable_name} | ConvertTo-Json -Depth 10"
            else:
                command = f"${variable_name}"
            
            await self._send_command(shell_process, command)
            stdout, _ = await self._read_output(shell_process)
            
            if as_json and stdout.strip():
                try:
                    return json.loads(stdout.strip())
                except json.JSONDecodeError:
                    return stdout.strip()
            
            return stdout.strip() if stdout.strip() else None
            
        except Exception as e:
            logger.error(
                "Failed to get PowerShell variable",
                variable=variable_name,
                error=str(e)
            )
            return None
    
    async def set_variable(
        self,
        shell_process: ShellProcess,
        variable_name: str,
        value: Any,
        scope: str = "Local"
    ) -> bool:
        """
        Set PowerShell variable.
        
        Args:
            shell_process: Shell process
            variable_name: Variable name (without $)
            value: Variable value
            scope: Variable scope (Local, Script, Global)
            
        Returns:
            Success status
        """
        try:
            if isinstance(value, str):
                command = f'${scope}:{variable_name} = "{value}"'
            elif isinstance(value, bool):
                command = f'${scope}:{variable_name} = ${str(value).lower()}'
            elif isinstance(value, (list, tuple)):
                # Create array
                array_str = ",".join(
                    f'"{v}"' if isinstance(v, str) else str(v) 
                    for v in value
                )
                command = f'${scope}:{variable_name} = @({array_str})'
            elif isinstance(value, dict):
                # Create hashtable
                hash_parts = []
                for k, v in value.items():
                    if isinstance(v, str):
                        hash_parts.append(f'{k} = "{v}"')
                    else:
                        hash_parts.append(f'{k} = {v}')
                command = f'${scope}:{variable_name} = @{{{"; ".join(hash_parts)}}}'
            else:
                command = f'${scope}:{variable_name} = {value}'
            
            await self._send_command(shell_process, command)
            return True
            
        except Exception as e:
            logger.error(
                "Failed to set PowerShell variable",
                variable=variable_name,
                error=str(e)
            )
            return False
    
    async def import_module(
        self,
        shell_process: ShellProcess,
        module_name: str,
        force: bool = False
    ) -> bool:
        """
        Import PowerShell module.
        
        Args:
            shell_process: Shell process
            module_name: Module name or path
            force: Force import
            
        Returns:
            Success status
        """
        try:
            command = f"Import-Module '{module_name}'"
            if force:
                command += " -Force"
            
            await self._send_command(shell_process, command)
            return True
            
        except Exception as e:
            logger.error(
                "Failed to import module",
                module=module_name,
                error=str(e)
            )
            return False
    
    async def test_path(
        self,
        shell_process: ShellProcess,
        path: Path
    ) -> Optional[bool]:
        """
        Test if path exists using Test-Path.
        
        Args:
            shell_process: Shell process
            path: Path to test
            
        Returns:
            True if exists, False if not, None on error
        """
        try:
            command = f"Test-Path '{path}'"
            
            await self._send_command(shell_process, command)
            stdout, _ = await self._read_output(shell_process)
            
            result = stdout.strip().lower()
            if result == "true":
                return True
            elif result == "false":
                return False
            else:
                return None
                
        except Exception as e:
            logger.error(
                "Failed to test path",
                path=str(path),
                error=str(e)
            )
            return None


class PowerShellShell(PowerShellBase):
    """Windows PowerShell implementation."""
    
    def __init__(
        self,
        settings: Optional[ShellSettings] = None,
        executable_path: Optional[Path] = None
    ):
        """
        Initialize Windows PowerShell.
        
        Args:
            settings: Shell configuration settings
            executable_path: Override path to powershell.exe
        """
        # Determine executable path
        if executable_path:
            ps_path = executable_path
        elif settings and settings.powershell_path:
            ps_path = settings.powershell_path
        else:
            ps_path = self._get_default_executable()
        
        super().__init__(
            shell_type=ShellType.POWERSHELL,
            settings=settings,
            executable_path=ps_path
        )
    
    def _get_default_executable(self) -> Path:
        """Get default powershell.exe path."""
        # Try standard locations
        standard_paths = [
            Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
            Path("C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell.exe"),
        ]
        
        for path in standard_paths:
            if path.exists():
                return path
        
        # Fall back to environment
        system_root = os.environ.get("SystemRoot", "C:\\Windows")
        return Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


class PwshShell(PowerShellBase):
    """PowerShell Core implementation."""
    
    def __init__(
        self,
        settings: Optional[ShellSettings] = None,
        executable_path: Optional[Path] = None
    ):
        """
        Initialize PowerShell Core.
        
        Args:
            settings: Shell configuration settings
            executable_path: Override path to pwsh.exe
        """
        # Determine executable path
        if executable_path:
            pwsh_path = executable_path
        elif settings and settings.pwsh_path:
            pwsh_path = settings.pwsh_path
        else:
            pwsh_path = self._get_default_executable()
        
        super().__init__(
            shell_type=ShellType.PWSH,
            settings=settings,
            executable_path=pwsh_path
        )
    
    def _get_default_executable(self) -> Path:
        """Get default pwsh.exe path."""
        # Try standard locations
        standard_paths = [
            Path("C:/Program Files/PowerShell/7/pwsh.exe"),
            Path("C:/Program Files (x86)/PowerShell/7/pwsh.exe"),
            Path.home() / ".dotnet/tools/pwsh.exe",
        ]
        
        # Check PATH
        import shutil
        pwsh_in_path = shutil.which("pwsh")
        if pwsh_in_path:
            standard_paths.insert(0, Path(pwsh_in_path))
        
        for path in standard_paths:
            if path.exists():
                return path
        
        # Fall back to most likely location
        return Path("C:/Program Files/PowerShell/7/pwsh.exe")
    
    def _get_startup_commands(self) -> List[str]:
        """Get PowerShell Core specific startup commands."""
        commands = super()._get_startup_commands()
        
        # Enable experimental features
        commands.append(
            "$PSDefaultParameterValues['*:EnableExperimentalFeature'] = $true"
        )
        
        return commands


def create_powershell_shell(
    shell_type: ShellType,
    settings: Optional[ShellSettings] = None
) -> Union[PowerShellShell, PwshShell]:
    """
    Factory function to create PowerShell instance.
    
    Args:
        shell_type: Type of PowerShell
        settings: Shell settings
        
    Returns:
        PowerShell instance
    """
    if shell_type == ShellType.POWERSHELL:
        return PowerShellShell(settings)
    elif shell_type == ShellType.PWSH:
        return PwshShell(settings)
    else:
        raise ValueError(f"Invalid PowerShell type: {shell_type}")