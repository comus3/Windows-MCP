"""
Session data models for MCP Windows Development Server.

This module defines the core data structures for managing sessions, including
session types, metadata, and lifecycle information.
"""

from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, ConfigDict
import structlog

logger = structlog.get_logger(__name__)


class SessionType(str, Enum):
    """
    Types of sessions supported by the MCP Windows server.
    
    Attributes:
        TEMPORARY: Short-lived sessions for quick tasks (auto-cleanup)
        PROJECT: Long-term project sessions (manual cleanup)
        EXPERIMENT: Experimental sessions with intermediate persistence
    """
    
    TEMPORARY = "temporary"
    PROJECT = "project"
    EXPERIMENT = "experiment"
    
    @classmethod
    def from_string(cls, value: str) -> "SessionType":
        """Convert string to SessionType with validation."""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(
                f"Invalid session type: {value}. "
                f"Must be one of: {', '.join(cls.__members__.keys())}"
            )
    
    @property
    def default_retention_days(self) -> int:
        """Get default retention period in days for this session type."""
        retention_map = {
            SessionType.TEMPORARY: 1,
            SessionType.EXPERIMENT: 30,
            SessionType.PROJECT: 365,
        }
        return retention_map.get(self, 7)
    
    @property
    def auto_cleanup(self) -> bool:
        """Whether this session type supports automatic cleanup."""
        return self in (SessionType.TEMPORARY, SessionType.EXPERIMENT)


class SessionState(str, Enum):
    """
    Current state of a session in its lifecycle.
    
    Attributes:
        INITIALIZING: Session is being created
        ACTIVE: Session is ready for use
        SUSPENDED: Session is temporarily inactive
        TERMINATING: Session is being cleaned up
        TERMINATED: Session has been removed
        ERROR: Session encountered an error
    """
    
    INITIALIZING = "initializing"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TERMINATING = "terminating"
    TERMINATED = "terminated"
    ERROR = "error"
    
    def can_transition_to(self, new_state: "SessionState") -> bool:
        """Check if transition to new state is valid."""
        valid_transitions = {
            SessionState.INITIALIZING: {SessionState.ACTIVE, SessionState.ERROR},
            SessionState.ACTIVE: {SessionState.SUSPENDED, SessionState.TERMINATING, SessionState.ERROR},
            SessionState.SUSPENDED: {SessionState.ACTIVE, SessionState.TERMINATING},
            SessionState.TERMINATING: {SessionState.TERMINATED, SessionState.ERROR},
            SessionState.TERMINATED: set(),
            SessionState.ERROR: {SessionState.TERMINATING},
        }
        return new_state in valid_transitions.get(self, set())


class ResourceLimits(BaseModel):
    """Resource limits for a session."""
    
    model_config = ConfigDict(frozen=True)
    
    max_memory_mb: int = Field(default=2048, ge=128, le=32768)
    max_processes: int = Field(default=50, ge=1, le=1000)
    max_execution_time_seconds: int = Field(default=3600, ge=60, le=86400)
    max_workspace_size_mb: int = Field(default=10240, ge=100, le=102400)
    max_open_files: int = Field(default=1000, ge=10, le=10000)
    cpu_limit_percent: Optional[int] = Field(default=None, ge=1, le=100)
    
    @field_validator("max_memory_mb")
    @classmethod
    def validate_memory(cls, v: int) -> int:
        """Ensure memory limit is reasonable."""
        import psutil
        total_memory_mb = psutil.virtual_memory().total // (1024 * 1024)
        if v > total_memory_mb * 0.5:
            logger.warning(
                "Session memory limit exceeds 50% of system memory",
                limit_mb=v,
                total_mb=total_memory_mb
            )
        return v


class SessionPermissions(BaseModel):
    """Security permissions for a session."""
    
    model_config = ConfigDict(frozen=True)
    
    network_access: bool = Field(default=False)
    registry_write: bool = Field(default=False)
    create_processes: bool = Field(default=True)
    debug_processes: bool = Field(default=False)
    load_drivers: bool = Field(default=False)
    system_time: bool = Field(default=False)
    create_symbolic_links: bool = Field(default=True)
    
    # Shell permissions
    allowed_shells: Set[str] = Field(
        default_factory=lambda: {"cmd", "powershell", "pwsh"}
    )
    
    # File operation permissions
    read_only_paths: List[Path] = Field(default_factory=list)
    read_write_paths: List[Path] = Field(default_factory=list)
    blocked_paths: List[Path] = Field(default_factory=list)
    
    @field_validator("allowed_shells")
    @classmethod
    def validate_shells(cls, v: Set[str]) -> Set[str]:
        """Ensure at least one shell is allowed."""
        if not v:
            raise ValueError("At least one shell must be allowed")
        return v


class SessionMetadata(BaseModel):
    """Metadata information for a session."""
    
    model_config = ConfigDict(frozen=True)
    
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=1000)
    tags: Set[str] = Field(default_factory=set)
    owner: str = Field(default="system")
    
    # Project information
    project_type: Optional[str] = Field(default=None)
    language: Optional[str] = Field(default=None)
    framework: Optional[str] = Field(default=None)
    
    # Custom metadata
    custom_data: Dict[str, Any] = Field(default_factory=dict)
    
    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: Set[str]) -> Set[str]:
        """Validate and normalize tags."""
        return {tag.lower().strip() for tag in v if tag.strip()}


class Session(BaseModel):
    """
    Complete session object representing an isolated workspace.
    
    This is the primary data structure for managing sessions in the
    MCP Windows server.
    """
    
    model_config = ConfigDict(validate_assignment=True)
    
    # Identity
    id: UUID = Field(default_factory=uuid4)
    type: SessionType
    state: SessionState = Field(default=SessionState.INITIALIZING)
    
    # Metadata
    metadata: SessionMetadata
    
    # Workspace
    workspace_path: Path
    workspace_id: str = Field(default_factory=lambda: str(uuid4()))
    
    # Security
    permissions: SessionPermissions = Field(default_factory=SessionPermissions)
    resource_limits: ResourceLimits = Field(default_factory=ResourceLimits)
    job_object_handle: Optional[int] = Field(default=None, exclude=True)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_accessed_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = Field(default=None)
    terminated_at: Optional[datetime] = Field(default=None)
    
    # Runtime state
    active_processes: List[int] = Field(default_factory=list, exclude=True)
    active_shells: Dict[str, Any] = Field(default_factory=dict, exclude=True)
    resource_usage: Dict[str, float] = Field(default_factory=dict)
    
    def __init__(self, **data):
        """Initialize session with automatic expiration calculation."""
        super().__init__(**data)
        
        # Set expiration based on session type if not provided
        if self.expires_at is None and self.type.auto_cleanup:
            retention_days = self.type.default_retention_days
            self.expires_at = self.created_at + timedelta(days=retention_days)
    
    @field_validator("workspace_path")
    @classmethod
    def validate_workspace_path(cls, v: Path) -> Path:
        """Ensure workspace path is absolute and valid."""
        if not v.is_absolute():
            raise ValueError("Workspace path must be absolute")
        return v
    
    @property
    def is_active(self) -> bool:
        """Check if session is currently active."""
        return self.state == SessionState.ACTIVE
    
    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    @property
    def age(self) -> timedelta:
        """Get age of the session."""
        return datetime.utcnow() - self.created_at
    
    @property
    def idle_time(self) -> timedelta:
        """Get time since last access."""
        return datetime.utcnow() - self.last_accessed_at
    
    def transition_state(self, new_state: SessionState) -> None:
        """
        Transition session to a new state with validation.
        
        Args:
            new_state: Target state for transition
            
        Raises:
            ValueError: If transition is not valid
        """
        if not self.state.can_transition_to(new_state):
            raise ValueError(
                f"Invalid state transition: {self.state} -> {new_state}"
            )
        
        old_state = self.state
        self.state = new_state
        
        # Update timestamps
        if new_state == SessionState.TERMINATED:
            self.terminated_at = datetime.utcnow()
        
        logger.info(
            "Session state transition",
            session_id=str(self.id),
            old_state=old_state.value,
            new_state=new_state.value
        )
    
    def touch(self) -> None:
        """Update last accessed timestamp."""
        self.last_accessed_at = datetime.utcnow()
    
    def update_resource_usage(self, usage: Dict[str, float]) -> None:
        """Update current resource usage metrics."""
        self.resource_usage.update(usage)
        self.touch()
    
    def add_process(self, pid: int) -> None:
        """Register a new process with the session."""
        if pid not in self.active_processes:
            self.active_processes.append(pid)
            logger.debug(
                "Process added to session",
                session_id=str(self.id),
                pid=pid,
                total_processes=len(self.active_processes)
            )
    
    def remove_process(self, pid: int) -> None:
        """Unregister a process from the session."""
        if pid in self.active_processes:
            self.active_processes.remove(pid)
            logger.debug(
                "Process removed from session",
                session_id=str(self.id),
                pid=pid,
                remaining_processes=len(self.active_processes)
            )
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert session to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive runtime data
            
        Returns:
            Dictionary representation of the session
        """
        data = self.model_dump(
            exclude={"job_object_handle", "active_processes", "active_shells"}
            if not include_sensitive else None
        )
        
        # Convert special types
        data["id"] = str(self.id)
        data["workspace_path"] = str(self.workspace_path)
        data["type"] = self.type.value
        data["state"] = self.state.value
        
        # Format timestamps
        for field in ["created_at", "last_accessed_at", "expires_at", "terminated_at"]:
            if data.get(field):
                data[field] = data[field].isoformat()
        
        return data
    
    def __str__(self) -> str:
        """String representation of session."""
        return (
            f"Session(id={self.id}, "
            f"type={self.type.value}, "
            f"state={self.state.value}, "
            f"name='{self.metadata.name}')"
        )
    
    def __repr__(self) -> str:
        """Developer representation of session."""
        return (
            f"Session(id={self.id!r}, "
            f"type={self.type!r}, "
            f"state={self.state!r}, "
            f"workspace_path={self.workspace_path!r})"
        )


class SessionSummary(BaseModel):
    """Lightweight session summary for listings."""
    
    model_config = ConfigDict(frozen=True)
    
    id: UUID
    type: SessionType
    state: SessionState
    name: str
    created_at: datetime
    last_accessed_at: datetime
    workspace_path: Path
    
    @classmethod
    def from_session(cls, session: Session) -> "SessionSummary":
        """Create summary from full session object."""
        return cls(
            id=session.id,
            type=session.type,
            state=session.state,
            name=session.metadata.name,
            created_at=session.created_at,
            last_accessed_at=session.last_accessed_at,
            workspace_path=session.workspace_path
        )