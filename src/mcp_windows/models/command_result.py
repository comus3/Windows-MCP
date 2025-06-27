"""
Command result models for MCP Windows Development Server.

This module defines data structures for representing command execution results,
including output, errors, and execution metadata.
"""

from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, ConfigDict
import structlog

logger = structlog.get_logger(__name__)


class CommandStatus(str, Enum):
    """
    Status of command execution.
    
    Attributes:
        PENDING: Command is queued but not started
        RUNNING: Command is currently executing
        SUCCESS: Command completed successfully
        FAILED: Command failed with non-zero exit code
        TIMEOUT: Command exceeded time limit
        CANCELLED: Command was cancelled by user
        ERROR: Command encountered system error
    """
    
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    ERROR = "error"
    
    @property
    def is_final(self) -> bool:
        """Check if this is a final (terminal) status."""
        return self in {
            CommandStatus.SUCCESS,
            CommandStatus.FAILED,
            CommandStatus.TIMEOUT,
            CommandStatus.CANCELLED,
            CommandStatus.ERROR
        }
    
    @property
    def is_error(self) -> bool:
        """Check if this status indicates an error."""
        return self in {
            CommandStatus.FAILED,
            CommandStatus.TIMEOUT,
            CommandStatus.ERROR
        }


class ShellType(str, Enum):
    """Supported shell types for command execution."""
    
    CMD = "cmd"
    POWERSHELL = "powershell"
    PWSH = "pwsh"  # PowerShell Core
    WSL = "wsl"
    GIT_BASH = "git_bash"
    
    @property
    def executable(self) -> str:
        """Get the executable name for this shell."""
        executables = {
            ShellType.CMD: "cmd.exe",
            ShellType.POWERSHELL: "powershell.exe",
            ShellType.PWSH: "pwsh.exe",
            ShellType.WSL: "wsl.exe",
            ShellType.GIT_BASH: "bash.exe"
        }
        return executables.get(self, self.value)
    
    @property
    def default_encoding(self) -> str:
        """Get default text encoding for this shell."""
        encodings = {
            ShellType.CMD: "cp1252",
            ShellType.POWERSHELL: "utf-8",
            ShellType.PWSH: "utf-8",
            ShellType.WSL: "utf-8",
            ShellType.GIT_BASH: "utf-8"
        }
        return encodings.get(self, "utf-8")


class CommandMetrics(BaseModel):
    """Performance metrics for command execution."""
    
    model_config = ConfigDict(frozen=True)
    
    cpu_time_seconds: float = Field(default=0.0, ge=0)
    peak_memory_mb: float = Field(default=0.0, ge=0)
    io_read_bytes: int = Field(default=0, ge=0)
    io_write_bytes: int = Field(default=0, ge=0)
    process_count: int = Field(default=1, ge=0)
    thread_count: int = Field(default=1, ge=0)
    
    @property
    def total_io_bytes(self) -> int:
        """Get total I/O bytes (read + write)."""
        return self.io_read_bytes + self.io_write_bytes


class CommandEnvironment(BaseModel):
    """Environment configuration for command execution."""
    
    model_config = ConfigDict(frozen=True)
    
    working_directory: Path
    environment_variables: Dict[str, str] = Field(default_factory=dict)
    shell_type: ShellType = Field(default=ShellType.CMD)
    encoding: Optional[str] = Field(default=None)
    timeout_seconds: Optional[int] = Field(default=300, ge=1, le=86400)
    
    @field_validator("working_directory")
    @classmethod
    def validate_working_directory(cls, v: Path) -> Path:
        """Ensure working directory is absolute."""
        if not v.is_absolute():
            raise ValueError("Working directory must be absolute path")
        return v
    
    @field_validator("encoding")
    @classmethod
    def validate_encoding(cls, v: Optional[str], values: Dict[str, Any]) -> Optional[str]:
        """Set default encoding based on shell if not provided."""
        if v is None and "shell_type" in values:
            return values["shell_type"].default_encoding
        return v


class CommandResult(BaseModel):
    """
    Complete result of command execution.
    
    This model captures all aspects of a command's execution including
    output, errors, timing, and resource usage.
    """
    
    model_config = ConfigDict(validate_assignment=True)
    
    # Identity
    id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    command: str
    
    # Execution details
    status: CommandStatus = Field(default=CommandStatus.PENDING)
    exit_code: Optional[int] = Field(default=None)
    signal: Optional[int] = Field(default=None)  # Unix signal if terminated
    
    # Output
    stdout: str = Field(default="")
    stderr: str = Field(default="")
    combined_output: Optional[str] = Field(default=None)
    
    # Environment
    environment: CommandEnvironment
    
    # Timing
    started_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)
    
    # Metrics
    metrics: Optional[CommandMetrics] = Field(default=None)
    
    # Process information
    process_id: Optional[int] = Field(default=None)
    child_processes: List[int] = Field(default_factory=list)
    
    # Error information
    error_message: Optional[str] = Field(default=None)
    error_details: Dict[str, Any] = Field(default_factory=dict)
    
    @property
    def duration(self) -> Optional[timedelta]:
        """Get command execution duration."""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Get command execution duration in seconds."""
        duration = self.duration
        return duration.total_seconds() if duration else None
    
    @property
    def is_complete(self) -> bool:
        """Check if command execution is complete."""
        return self.status.is_final
    
    @property
    def is_success(self) -> bool:
        """Check if command executed successfully."""
        return self.status == CommandStatus.SUCCESS
    
    @property
    def has_output(self) -> bool:
        """Check if command produced any output."""
        return bool(self.stdout or self.stderr)
    
    @property
    def total_output_size(self) -> int:
        """Get total size of output in bytes."""
        return len(self.stdout.encode()) + len(self.stderr.encode())
    
    def start_execution(self, process_id: int) -> None:
        """
        Mark command as started.
        
        Args:
            process_id: ID of the main process
        """
        self.status = CommandStatus.RUNNING
        self.started_at = datetime.utcnow()
        self.process_id = process_id
        
        logger.info(
            "Command execution started",
            command_id=str(self.id),
            session_id=str(self.session_id),
            process_id=process_id
        )
    
    def complete_execution(
        self,
        exit_code: int,
        stdout: str = "",
        stderr: str = "",
        metrics: Optional[CommandMetrics] = None
    ) -> None:
        """
        Mark command as completed.
        
        Args:
            exit_code: Process exit code
            stdout: Standard output
            stderr: Standard error
            metrics: Performance metrics
        """
        self.completed_at = datetime.utcnow()
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.metrics = metrics
        
        # Set final status
        if exit_code == 0:
            self.status = CommandStatus.SUCCESS
        else:
            self.status = CommandStatus.FAILED
        
        # Combine output if both streams present
        if stdout and stderr:
            self.combined_output = f"{stdout}\n--- STDERR ---\n{stderr}"
        
        logger.info(
            "Command execution completed",
            command_id=str(self.id),
            status=self.status.value,
            exit_code=exit_code,
            duration_seconds=self.duration_seconds
        )
    
    def timeout_execution(self) -> None:
        """Mark command as timed out."""
        self.status = CommandStatus.TIMEOUT
        self.completed_at = datetime.utcnow()
        self.error_message = f"Command exceeded timeout of {self.environment.timeout_seconds} seconds"
        
        logger.warning(
            "Command execution timed out",
            command_id=str(self.id),
            timeout_seconds=self.environment.timeout_seconds
        )
    
    def cancel_execution(self, reason: str = "User cancelled") -> None:
        """
        Mark command as cancelled.
        
        Args:
            reason: Cancellation reason
        """
        self.status = CommandStatus.CANCELLED
        self.completed_at = datetime.utcnow()
        self.error_message = reason
        
        logger.info(
            "Command execution cancelled",
            command_id=str(self.id),
            reason=reason
        )
    
    def error_execution(self, error: Exception) -> None:
        """
        Mark command as errored.
        
        Args:
            error: Exception that occurred
        """
        self.status = CommandStatus.ERROR
        self.completed_at = datetime.utcnow()
        self.error_message = str(error)
        self.error_details = {
            "type": type(error).__name__,
            "args": error.args if hasattr(error, "args") else []
        }
        
        logger.error(
            "Command execution error",
            command_id=str(self.id),
            error_type=type(error).__name__,
            error_message=str(error)
        )
    
    def add_child_process(self, pid: int) -> None:
        """Register a child process."""
        if pid not in self.child_processes:
            self.child_processes.append(pid)
    
    def append_output(self, stdout: str = "", stderr: str = "") -> None:
        """
        Append output to existing streams.
        
        Args:
            stdout: Additional standard output
            stderr: Additional standard error
        """
        if stdout:
            self.stdout += stdout
        if stderr:
            self.stderr += stderr
    
    def to_dict(self, include_output: bool = True) -> Dict[str, Any]:
        """
        Convert result to dictionary representation.
        
        Args:
            include_output: Whether to include stdout/stderr
            
        Returns:
            Dictionary representation
        """
        data = self.model_dump(
            exclude={"stdout", "stderr", "combined_output"} if not include_output else None
        )
        
        # Convert special types
        data["id"] = str(self.id)
        data["session_id"] = str(self.session_id)
        data["status"] = self.status.value
        
        # Format timestamps
        for field in ["started_at", "completed_at"]:
            if data.get(field):
                data[field] = data[field].isoformat()
        
        # Add computed properties
        data["duration_seconds"] = self.duration_seconds
        data["is_success"] = self.is_success
        
        return data
    
    def __str__(self) -> str:
        """String representation of command result."""
        return (
            f"CommandResult(id={self.id}, "
            f"command='{self.command[:50]}...', "
            f"status={self.status.value}, "
            f"exit_code={self.exit_code})"
        )


class CommandBatch(BaseModel):
    """Result of executing multiple commands in sequence."""
    
    model_config = ConfigDict(frozen=True)
    
    id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    results: List[CommandResult]
    stop_on_error: bool = Field(default=True)
    parallel: bool = Field(default=False)
    
    @property
    def total_commands(self) -> int:
        """Get total number of commands."""
        return len(self.results)
    
    @property
    def successful_commands(self) -> int:
        """Get number of successful commands."""
        return sum(1 for r in self.results if r.is_success)
    
    @property
    def failed_commands(self) -> int:
        """Get number of failed commands."""
        return sum(1 for r in self.results if r.status.is_error)
    
    @property
    def is_success(self) -> bool:
        """Check if all commands succeeded."""
        return all(r.is_success for r in self.results)
    
    @property
    def first_error(self) -> Optional[CommandResult]:
        """Get the first command that errored."""
        for result in self.results:
            if result.status.is_error:
                return result
        return None