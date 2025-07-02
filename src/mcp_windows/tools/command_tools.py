"""
Command execution tools for MCP Windows Development Server.

This module provides MCP tool implementations for command execution,
shell management, and process control.
"""

from typing import Any, Dict, List, Optional
from pathlib import Path
from uuid import UUID
import json

from fastmcp import FastMCP, Context
from pydantic import BaseModel, Field

from ..core.command_executor import CommandExecutor
from ..models.command_result import ShellType
from ..utils.logging_config import get_logger

logger = get_logger(__name__)


# Tool parameter models
class ExecuteCommandParams(BaseModel):
    """Parameters for execute_command tool."""
    
    command: str = Field(
        description="Command to execute"
    )
    session_id: str = Field(
        description="Session ID for execution context"
    )
    shell: Optional[str] = Field(
        default=None,
        description="Shell to use: cmd, powershell, or pwsh"
    )
    working_directory: Optional[str] = Field(
        default=None,
        description="Working directory (defaults to workspace root)"
    )
    timeout: Optional[int] = Field(
        default=None,
        description="Command timeout in seconds"
    )
    environment: Optional[Dict[str, str]] = Field(
        default=None,
        description="Environment variables to set"
    )


class ExecutePowerShellScriptParams(BaseModel):
    """Parameters for execute_powershell_script tool."""
    
    script: str = Field(
        description="PowerShell script content"
    )
    session_id: str = Field(
        description="Session ID for execution context"
    )
    use_core: bool = Field(
        default=False,
        description="Use PowerShell Core (pwsh) instead of Windows PowerShell"
    )
    execution_policy: Optional[str] = Field(
        default=None,
        description="Override execution policy"
    )
    parameters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Parameters to pass to the script"
    )
    timeout: Optional[int] = Field(
        default=None,
        description="Script timeout in seconds"
    )


class ExecuteBatchCommandsParams(BaseModel):
    """Parameters for execute_batch_commands tool."""
    
    commands: List[str] = Field(
        description="List of commands to execute"
    )
    session_id: str = Field(
        description="Session ID for execution context"
    )
    shell: Optional[str] = Field(
        default=None,
        description="Shell to use for all commands"
    )
    stop_on_error: bool = Field(
        default=True,
        description="Stop execution on first error"
    )
    parallel: bool = Field(
        default=False,
        description="Execute commands in parallel"
    )


class CommandTools:
    """MCP tools for command execution."""
    
    def __init__(self, mcp: FastMCP, command_executor: CommandExecutor):
        """
        Initialize command tools.
        
        Args:
            mcp: FastMCP server instance
            command_executor: Command executor instance
        """
        self.mcp = mcp
        self.command_executor = command_executor
        
        # Register tools
        self._register_tools()
    
    def _register_tools(self) -> None:
        """Register all command tools with MCP."""
        
        @self.mcp.tool()
        async def execute_command(
            command: str,
            session_id: str,
            shell: Optional[str] = None,
            working_directory: Optional[str] = None,
            timeout: Optional[int] = None,
            environment: Optional[Dict[str, str]] = None,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Execute a command in a workspace session.
            
            Runs a command in the specified shell with proper isolation and
            security controls. Output is captured and returned.
            
            Args:
                command: Command to execute
                session_id: Session ID for execution context
                shell: Shell to use (cmd, powershell, pwsh). Auto-detected if not specified.
                working_directory: Working directory (defaults to workspace root)
                timeout: Command timeout in seconds
                environment: Additional environment variables
                
            Returns:
                Dictionary with execution results including stdout, stderr, and exit code
            """
            try:
                # Parse session ID
                try:
                    session_uuid = UUID(session_id)
                except ValueError:
                    return {"error": f"Invalid session ID: {session_id}"}
                
                # Parse shell type
                shell_type = None
                if shell:
                    try:
                        shell_type = ShellType(shell.lower())
                    except ValueError:
                        return {
                            "error": f"Invalid shell type: {shell}. "
                                    f"Must be one of: cmd, powershell, pwsh"
                        }
                
                # Parse working directory
                work_dir = None
                if working_directory:
                    work_dir = Path(working_directory)
                    if not work_dir.is_absolute():
                        return {"error": "Working directory must be an absolute path"}
                
                # Execute command
                result = await self.command_executor.execute_command(
                    command=command,
                    session_id=session_uuid,
                    shell_type=shell_type,
                    working_directory=work_dir,
                    environment_variables=environment,
                    timeout=timeout
                )
                
                logger.info(
                    "Executed command via MCP",
                    session_id=session_id,
                    command_truncated=command[:50],
                    exit_code=result.exit_code
                )
                
                return {
                    "command_id": str(result.id),
                    "command": result.command,
                    "status": result.status.value,
                    "exit_code": result.exit_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "shell": result.environment.shell_type.value,
                    "working_directory": str(result.environment.working_directory),
                    "started_at": result.started_at.isoformat() if result.started_at else None,
                    "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                    "duration_seconds": result.duration_seconds,
                    "error_message": result.error_message,
                    "timed_out": result.status.value == "timeout"
                }
                
            except Exception as e:
                logger.error(
                    "Failed to execute command",
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def execute_powershell_script(
            script: str,
            session_id: str,
            use_core: bool = False,
            execution_policy: Optional[str] = None,
            parameters: Optional[Dict[str, Any]] = None,
            timeout: Optional[int] = None,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Execute a PowerShell script.
            
            Runs PowerShell script content with proper parameter handling
            and execution policy control.
            
            Args:
                script: PowerShell script content to execute
                session_id: Session ID for execution context
                use_core: Use PowerShell Core (pwsh) instead of Windows PowerShell
                execution_policy: Override execution policy (e.g., RemoteSigned, Bypass)
                parameters: Parameters to pass to the script
                timeout: Script timeout in seconds
                
            Returns:
                Dictionary with script execution results
            """
            try:
                # Parse session ID
                try:
                    session_uuid = UUID(session_id)
                except ValueError:
                    return {"error": f"Invalid session ID: {session_id}"}
                
                # Choose shell
                shell_type = ShellType.PWSH if use_core else ShellType.POWERSHELL
                
                # Build script command
                if parameters:
                    # Create parameter block
                    param_lines = []
                    for name, value in parameters.items():
                        if isinstance(value, str):
                            param_lines.append(f"$param{name} = '{value}'")
                        elif isinstance(value, bool):
                            param_lines.append(f"$param{name} = ${str(value).lower()}")
                        elif isinstance(value, (list, tuple)):
                            array_str = ",".join(
                                f"'{v}'" if isinstance(v, str) else str(v)
                                for v in value
                            )
                            param_lines.append(f"$param{name} = @({array_str})")
                        else:
                            param_lines.append(f"$param{name} = {value}")
                    
                    # Prepend parameters to script
                    full_script = "\n".join(param_lines) + "\n\n" + script
                else:
                    full_script = script
                
                # Encode script for command line
                import base64
                encoded_script = base64.b64encode(
                    full_script.encode('utf-16-le')
                ).decode('ascii')
                
                # Build command
                command = f"-EncodedCommand {encoded_script}"
                
                # Add execution policy if specified
                if execution_policy:
                    command = f"-ExecutionPolicy {execution_policy} {command}"
                
                # Execute
                result = await self.command_executor.execute_command(
                    command=command,
                    session_id=session_uuid,
                    shell_type=shell_type,
                    timeout=timeout
                )
                
                logger.info(
                    "Executed PowerShell script via MCP",
                    session_id=session_id,
                    use_core=use_core,
                    exit_code=result.exit_code
                )
                
                return {
                    "command_id": str(result.id),
                    "status": result.status.value,
                    "exit_code": result.exit_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "shell": shell_type.value,
                    "execution_policy": execution_policy,
                    "started_at": result.started_at.isoformat() if result.started_at else None,
                    "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                    "duration_seconds": result.duration_seconds,
                    "error_message": result.error_message,
                    "timed_out": result.status.value == "timeout"
                }
                
            except Exception as e:
                logger.error(
                    "Failed to execute PowerShell script",
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def execute_batch_commands(
            commands: List[str],
            session_id: str,
            shell: Optional[str] = None,
            stop_on_error: bool = True,
            parallel: bool = False,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Execute multiple commands in sequence or parallel.
            
            Runs a batch of commands with options for error handling and
            parallel execution.
            
            Args:
                commands: List of commands to execute
                session_id: Session ID for execution context
                shell: Shell to use for all commands
                stop_on_error: Stop execution on first error
                parallel: Execute commands in parallel instead of sequentially
                
            Returns:
                Dictionary with batch execution results
            """
            try:
                # Parse session ID
                try:
                    session_uuid = UUID(session_id)
                except ValueError:
                    return {"error": f"Invalid session ID: {session_id}"}
                
                # Parse shell type
                shell_type = None
                if shell:
                    try:
                        shell_type = ShellType(shell.lower())
                    except ValueError:
                        return {
                            "error": f"Invalid shell type: {shell}. "
                                    f"Must be one of: cmd, powershell, pwsh"
                        }
                
                # Execute batch
                batch_result = await self.command_executor.execute_batch_commands(
                    commands=commands,
                    session_id=session_uuid,
                    shell_type=shell_type,
                    stop_on_error=stop_on_error,
                    parallel=parallel
                )
                
                # Format results
                results = []
                for result in batch_result.results:
                    results.append({
                        "command": result.command,
                        "status": result.status.value,
                        "exit_code": result.exit_code,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "duration_seconds": result.duration_seconds,
                        "error_message": result.error_message
                    })
                
                logger.info(
                    "Executed batch commands via MCP",
                    session_id=session_id,
                    total_commands=batch_result.total_commands,
                    successful=batch_result.successful_commands,
                    failed=batch_result.failed_commands,
                    parallel=parallel
                )
                
                return {
                    "batch_id": str(batch_result.id),
                    "session_id": session_id,
                    "total_commands": batch_result.total_commands,
                    "successful_commands": batch_result.successful_commands,
                    "failed_commands": batch_result.failed_commands,
                    "is_success": batch_result.is_success,
                    "stop_on_error": stop_on_error,
                    "parallel": parallel,
                    "results": results
                }
                
            except Exception as e:
                logger.error(
                    "Failed to execute batch commands",
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def get_active_commands(
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Get list of currently executing commands.
            
            Returns information about all commands that are currently running
            across all sessions.
            
            Returns:
                Dictionary with list of active commands
            """
            try:
                active = await self.command_executor.get_active_commands()
                
                commands = []
                for cmd in active:
                    commands.append({
                        "command_id": str(cmd.id),
                        "session_id": str(cmd.session_id),
                        "command": cmd.command[:100],  # Truncate for display
                        "status": cmd.status.value,
                        "shell": cmd.environment.shell_type.value,
                        "started_at": cmd.started_at.isoformat() if cmd.started_at else None,
                        "duration_seconds": (
                            (datetime.utcnow() - cmd.started_at).total_seconds()
                            if cmd.started_at else 0
                        )
                    })
                
                return {
                    "active_commands": commands,
                    "count": len(commands)
                }
                
            except Exception as e:
                logger.error(
                    "Failed to get active commands",
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def cancel_command(
            command_id: str,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Cancel a running command.
            
            Attempts to terminate a command that is currently executing.
            
            Args:
                command_id: ID of the command to cancel
                
            Returns:
                Dictionary with cancellation status
            """
            try:
                # Parse command ID
                try:
                    cmd_uuid = UUID(command_id)
                except ValueError:
                    return {"error": f"Invalid command ID: {command_id}"}
                
                # Cancel command
                success = await self.command_executor.cancel_command(cmd_uuid)
                
                if success:
                    logger.info(
                        "Cancelled command via MCP",
                        command_id=command_id
                    )
                    
                    return {
                        "success": True,
                        "command_id": command_id,
                        "message": "Command cancelled successfully"
                    }
                else:
                    return {
                        "success": False,
                        "error": "Command not found or already completed"
                    }
                    
            except Exception as e:
                logger.error(
                    "Failed to cancel command",
                    command_id=command_id,
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def get_shell_info(
            session_id: str,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Get information about available shells for a session.
            
            Returns details about which shells are available and allowed
            for the specified session.
            
            Args:
                session_id: Session ID to check
                
            Returns:
                Dictionary with shell availability information
            """
            try:
                # Parse session ID
                try:
                    session_uuid = UUID(session_id)
                except ValueError:
                    return {"error": f"Invalid session ID: {session_id}"}
                
                # Get session
                if not self.command_executor.session_manager:
                    return {"error": "Session manager not available"}
                
                session = await self.command_executor.session_manager.get_session(session_uuid)
                if not session:
                    return {"error": f"Session not found: {session_id}"}
                
                # Get available shells
                available_shells = self.command_executor._shell_factory.get_available_shells()
                
                # Build shell info
                shells = {}
                for shell_type, shell in available_shells.items():
                    allowed = shell_type.value in session.permissions.allowed_shells
                    shells[shell_type.value] = {
                        "available": True,
                        "allowed": allowed,
                        "executable": str(shell.executable_path),
                        "encoding": shell.default_encoding
                    }
                
                # Add unavailable but allowed shells
                for shell_name in session.permissions.allowed_shells:
                    if shell_name not in shells:
                        shells[shell_name] = {
                            "available": False,
                            "allowed": True,
                            "executable": None,
                            "encoding": None
                        }
                
                return {
                    "session_id": session_id,
                    "shells": shells,
                    "default_shell": "cmd",
                    "recommended_shell": self._get_recommended_shell(shells)
                }
                
            except Exception as e:
                logger.error(
                    "Failed to get shell info",
                    session_id=session_id,
                    error=str(e)
                )
                return {"error": str(e)}
    
    def _get_recommended_shell(self, shells: Dict[str, Dict[str, Any]]) -> str:
        """Get recommended shell based on availability."""
        # Preference order
        preferences = ["pwsh", "powershell", "cmd"]
        
        for pref in preferences:
            shell_info = shells.get(pref, {})
            if shell_info.get("available") and shell_info.get("allowed"):
                return pref
        
        return "cmd"  # Default fallback