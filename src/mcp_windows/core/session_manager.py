"""
Session manager for MCP Windows Development Server.

This module manages session lifecycle including creation, persistence,
type conversion, and cleanup operations.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from uuid import UUID
from collections import defaultdict
import pickle

import aiofiles
import structlog

from ..config.settings import MCPWindowsSettings
from ..models.session import (
    Session, SessionType, SessionState, SessionMetadata,
    SessionPermissions, ResourceLimits, SessionSummary
)
from ..utils.logging_config import get_logger, AuditLogger
from ..utils.path_utils import PathUtils

logger = get_logger(__name__)


class SessionStore:
    """Persistent storage for session data."""
    
    def __init__(self, store_path: Path):
        """
        Initialize session store.
        
        Args:
            store_path: Path to session storage directory
        """
        self.store_path = store_path
        self.store_path.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
    
    async def save_session(self, session: Session) -> bool:
        """
        Save session to persistent storage.
        
        Args:
            session: Session to save
            
        Returns:
            Success status
        """
        async with self._lock:
            try:
                session_file = self._get_session_file(session.id)
                
                # Convert to JSON-serializable format
                data = session.to_dict(include_sensitive=True)
                
                # Write atomically
                temp_file = session_file.with_suffix('.tmp')
                async with aiofiles.open(temp_file, 'w') as f:
                    await f.write(json.dumps(data, indent=2))
                
                # Move to final location
                temp_file.replace(session_file)
                
                logger.debug(
                    "Saved session to store",
                    session_id=str(session.id),
                    file=str(session_file)
                )
                
                return True
                
            except Exception as e:
                logger.error(
                    "Failed to save session",
                    session_id=str(session.id),
                    error=str(e)
                )
                return False
    
    async def load_session(self, session_id: UUID) -> Optional[Session]:
        """
        Load session from persistent storage.
        
        Args:
            session_id: Session ID to load
            
        Returns:
            Session or None if not found
        """
        async with self._lock:
            try:
                session_file = self._get_session_file(session_id)
                
                if not session_file.exists():
                    return None
                
                async with aiofiles.open(session_file, 'r') as f:
                    data = json.loads(await f.read())
                
                # Reconstruct session
                session = self._reconstruct_session(data)
                
                logger.debug(
                    "Loaded session from store",
                    session_id=str(session_id)
                )
                
                return session
                
            except Exception as e:
                logger.error(
                    "Failed to load session",
                    session_id=str(session_id),
                    error=str(e)
                )
                return None
    
    async def delete_session(self, session_id: UUID) -> bool:
        """
        Delete session from storage.
        
        Args:
            session_id: Session ID to delete
            
        Returns:
            Success status
        """
        async with self._lock:
            try:
                session_file = self._get_session_file(session_id)
                
                if session_file.exists():
                    session_file.unlink()
                
                return True
                
            except Exception as e:
                logger.error(
                    "Failed to delete session",
                    session_id=str(session_id),
                    error=str(e)
                )
                return False
    
    async def list_sessions(self) -> List[UUID]:
        """
        List all stored session IDs.
        
        Returns:
            List of session IDs
        """
        async with self._lock:
            session_ids = []
            
            for file in self.store_path.glob("*.json"):
                if file.stem.count('-') == 4:  # UUID format
                    try:
                        session_ids.append(UUID(file.stem))
                    except ValueError:
                        pass
            
            return session_ids
    
    def _get_session_file(self, session_id: UUID) -> Path:
        """Get session file path."""
        return self.store_path / f"{session_id}.json"
    
    def _reconstruct_session(self, data: Dict[str, Any]) -> Session:
        """Reconstruct session from stored data."""
        # Parse timestamps
        for field in ["created_at", "last_accessed_at", "expires_at", "terminated_at"]:
            if data.get(field):
                data[field] = datetime.fromisoformat(data[field])
        
        # Parse enums
        data["type"] = SessionType(data["type"])
        data["state"] = SessionState(data["state"])
        
        # Parse paths
        data["workspace_path"] = Path(data["workspace_path"])
        
        # Parse nested models
        data["metadata"] = SessionMetadata(**data["metadata"])
        data["permissions"] = SessionPermissions(**data["permissions"])
        data["resource_limits"] = ResourceLimits(**data["resource_limits"])
        
        # Parse UUID
        data["id"] = UUID(data["id"])
        
        return Session(**data)


class SessionManager:
    """
    Manages session lifecycle for MCP Windows server.
    
    This class handles:
    - Session creation and initialization
    - Session state transitions
    - Session persistence and recovery
    - Session type conversion
    - Cleanup and expiration
    """
    
    def __init__(
        self,
        settings: MCPWindowsSettings,
        workspace_manager=None,
        security_manager=None
    ):
        """
        Initialize session manager.
        
        Args:
            settings: Application settings
            workspace_manager: Workspace manager instance
            security_manager: Security manager instance
        """
        self.settings = settings
        self.workspace_manager = workspace_manager
        self.security_manager = security_manager
        
        # Session storage
        self._sessions: Dict[UUID, Session] = {}
        self._session_store = SessionStore(
            settings.workspace.root_directory / ".sessions"
        )
        
        # Audit logging
        self._audit_logger = AuditLogger(
            settings.workspace.root_directory / ".audit" / "sessions.log"
        )
        
        # Session limits
        self._max_sessions = settings.max_sessions
        self._session_idle_timeout = (
            timedelta(minutes=settings.session_idle_timeout_minutes)
            if settings.session_idle_timeout_minutes else None
        )
        
        # Cleanup task
        self._cleanup_task = None
        self._cleanup_interval = timedelta(
            hours=settings.workspace.cleanup_interval_hours
        )
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
        
        logger.info(
            "Session manager initialized",
            max_sessions=self._max_sessions,
            cleanup_enabled=settings.workspace.cleanup_enabled
        )
    
    async def initialize(self) -> None:
        """Initialize session manager and restore sessions."""
        async with self._lock:
            # Load existing sessions
            session_ids = await self._session_store.list_sessions()
            restored = 0
            
            for session_id in session_ids:
                try:
                    session = await self._session_store.load_session(session_id)
                    if session and session.state != SessionState.TERMINATED:
                        self._sessions[session.id] = session
                        
                        # Transition to active if was initializing
                        if session.state == SessionState.INITIALIZING:
                            session.transition_state(SessionState.ACTIVE)
                        
                        restored += 1
                except Exception as e:
                    logger.error(
                        "Failed to restore session",
                        session_id=str(session_id),
                        error=str(e)
                    )
            
            logger.info(
                "Session manager initialized",
                restored_sessions=restored,
                total_stored=len(session_ids)
            )
            
            # Start cleanup task
            if self.settings.workspace.cleanup_enabled:
                self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def create_session(
        self,
        session_type: SessionType,
        metadata: SessionMetadata,
        permissions: Optional[SessionPermissions] = None,
        resource_limits: Optional[ResourceLimits] = None,
        auto_cleanup_days: Optional[int] = None
    ) -> Session:
        """
        Create a new session.
        
        Args:
            session_type: Type of session
            metadata: Session metadata
            permissions: Security permissions
            resource_limits: Resource limits
            auto_cleanup_days: Override auto-cleanup period
            
        Returns:
            Created session
            
        Raises:
            ValueError: If session limit reached
        """
        async with self._lock:
            # Check session limit
            active_count = sum(
                1 for s in self._sessions.values()
                if s.state not in {SessionState.TERMINATED, SessionState.ERROR}
            )
            
            if active_count >= self._max_sessions:
                raise ValueError(
                    f"Session limit reached ({self._max_sessions} max)"
                )
            
            # Create workspace
            if not self.workspace_manager:
                raise RuntimeError("Workspace manager not available")
            
            workspace_path = await self.workspace_manager.create_workspace(
                session_type=session_type,
                session_name=metadata.name
            )
            
            # Create session
            session = Session(
                type=session_type,
                metadata=metadata,
                workspace_path=workspace_path,
                permissions=permissions or SessionPermissions(),
                resource_limits=resource_limits or ResourceLimits()
            )
            
            # Set custom expiration
            if auto_cleanup_days is not None:
                session.expires_at = session.created_at + timedelta(days=auto_cleanup_days)
            
            # Create job object if security manager available
            if self.security_manager:
                job_handle = await self.security_manager.create_job_object(session)
                session.job_object_handle = job_handle
            
            # Initialize workspace structure
            await self.workspace_manager.initialize_workspace_structure(
                workspace_path,
                create_defaults=self.settings.workspace.create_default_structure
            )
            
            # Set permissions on workspace
            if self.security_manager:
                await self.security_manager.set_path_permissions(
                    workspace_path,
                    session,
                    session.permissions.READ_WRITE
                )
            
            # Transition to active
            session.transition_state(SessionState.ACTIVE)
            
            # Store session
            self._sessions[session.id] = session
            await self._session_store.save_session(session)
            
            # Audit log
            self._audit_logger.log_session_created(
                str(session.id),
                session_type.value,
                metadata.owner,
                str(workspace_path)
            )
            
            logger.info(
                "Created session",
                session_id=str(session.id),
                type=session_type.value,
                name=metadata.name,
                workspace=str(workspace_path)
            )
            
            return session
    
    async def get_session(self, session_id: UUID) -> Optional[Session]:
        """
        Get session by ID.
        
        Args:
            session_id: Session ID
            
        Returns:
            Session or None if not found
        """
        async with self._lock:
            session = self._sessions.get(session_id)
            
            if session:
                # Update last accessed
                session.touch()
                
                # Check if expired
                if session.is_expired and session.state == SessionState.ACTIVE:
                    session.transition_state(SessionState.SUSPENDED)
                    await self._session_store.save_session(session)
            
            return session
    
    async def list_sessions(
        self,
        include_terminated: bool = False,
        session_type: Optional[SessionType] = None
    ) -> List[SessionSummary]:
        """
        List all sessions.
        
        Args:
            include_terminated: Include terminated sessions
            session_type: Filter by session type
            
        Returns:
            List of session summaries
        """
        async with self._lock:
            summaries = []
            
            for session in self._sessions.values():
                # Filter terminated
                if not include_terminated and session.state == SessionState.TERMINATED:
                    continue
                
                # Filter by type
                if session_type and session.type != session_type:
                    continue
                
                summaries.append(SessionSummary.from_session(session))
            
            return sorted(summaries, key=lambda s: s.created_at, reverse=True)
    
    async def delete_session(
        self,
        session_id: UUID,
        force: bool = False
    ) -> bool:
        """
        Delete a session.
        
        Args:
            session_id: Session ID to delete
            force: Force deletion even if active
            
        Returns:
            Success status
        """
        async with self._lock:
            session = self._sessions.get(session_id)
            
            if not session:
                return False
            
            # Check if can delete
            if not force and session.state == SessionState.ACTIVE:
                logger.warning(
                    "Cannot delete active session",
                    session_id=str(session_id)
                )
                return False
            
            # Terminate processes
            if self.security_manager:
                terminated = await self.security_manager.terminate_session_processes(
                    str(session_id)
                )
                logger.info(
                    "Terminated session processes",
                    session_id=str(session_id),
                    count=terminated
                )
            
            # Clean up job object
            if self.security_manager and session.job_object_handle:
                await self.security_manager.cleanup_job_object(str(session_id))
            
            # Clean up workspace
            if self.workspace_manager:
                await self.workspace_manager.delete_workspace(
                    session.workspace_path,
                    force=force
                )
            
            # Update state
            session.transition_state(SessionState.TERMINATED)
            
            # Remove from active sessions
            del self._sessions[session_id]
            
            # Update storage
            await self._session_store.save_session(session)
            
            logger.info(
                "Deleted session",
                session_id=str(session_id),
                forced=force
            )
            
            return True
    
    async def convert_session_type(
        self,
        session_id: UUID,
        new_type: SessionType,
        new_name: Optional[str] = None
    ) -> bool:
        """
        Convert session to different type.
        
        Args:
            session_id: Session to convert
            new_type: New session type
            new_name: New name for session
            
        Returns:
            Success status
        """
        async with self._lock:
            session = self._sessions.get(session_id)
            
            if not session:
                return False
            
            # Check if conversion allowed
            if session.state != SessionState.ACTIVE:
                logger.warning(
                    "Cannot convert non-active session",
                    session_id=str(session_id),
                    state=session.state.value
                )
                return False
            
            old_type = session.type
            
            # Update session
            session.type = new_type
            
            # Update name if provided
            if new_name:
                session.metadata.name = new_name
            
            # Update expiration based on new type
            if new_type.auto_cleanup:
                retention_days = new_type.default_retention_days
                session.expires_at = datetime.utcnow() + timedelta(days=retention_days)
            else:
                session.expires_at = None
            
            # Save changes
            await self._session_store.save_session(session)
            
            logger.info(
                "Converted session type",
                session_id=str(session_id),
                old_type=old_type.value,
                new_type=new_type.value
            )
            
            return True
    
    async def analyze_workspace_for_project_type(
        self,
        session_id: UUID
    ) -> Dict[str, Any]:
        """
        Analyze workspace to determine project type.
        
        Args:
            session_id: Session to analyze
            
        Returns:
            Analysis results
        """
        async with self._lock:
            session = self._sessions.get(session_id)
            
            if not session:
                return {"error": "Session not found"}
            
            if not self.workspace_manager:
                return {"error": "Workspace manager not available"}
            
            # Analyze workspace
            analysis = await self.workspace_manager.analyze_workspace(
                session.workspace_path
            )
            
            # Determine project type
            project_info = self._infer_project_type(analysis)
            
            # Update session metadata if detected
            if project_info["detected"]:
                session.metadata.project_type = project_info["type"]
                session.metadata.language = project_info.get("language")
                session.metadata.framework = project_info.get("framework")
                
                await self._session_store.save_session(session)
            
            return {
                "session_id": str(session_id),
                "workspace_path": str(session.workspace_path),
                "analysis": analysis,
                "project_info": project_info,
                "recommendation": self._get_type_recommendation(project_info)
            }
    
    def _infer_project_type(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Infer project type from workspace analysis."""
        files = analysis.get("files", {})
        
        # Check for common project files
        project_indicators = {
            "package.json": ("node", "JavaScript", "Node.js"),
            "requirements.txt": ("python", "Python", None),
            "pyproject.toml": ("python", "Python", None),
            "Cargo.toml": ("rust", "Rust", None),
            "go.mod": ("go", "Go", None),
            "pom.xml": ("java", "Java", "Maven"),
            "build.gradle": ("java", "Java", "Gradle"),
            "*.csproj": ("dotnet", "C#", ".NET"),
            "composer.json": ("php", "PHP", None),
            "Gemfile": ("ruby", "Ruby", None),
        }
        
        for pattern, (proj_type, language, framework) in project_indicators.items():
            if pattern.startswith("*"):
                # Wildcard pattern
                ext = pattern[1:]
                if any(f.endswith(ext) for f in files):
                    return {
                        "detected": True,
                        "type": proj_type,
                        "language": language,
                        "framework": framework
                    }
            elif pattern in files:
                return {
                    "detected": True,
                    "type": proj_type,
                    "language": language,
                    "framework": framework
                }
        
        # Check directory structure
        dirs = analysis.get("directories", [])
        if "src" in dirs and "tests" in dirs:
            return {
                "detected": True,
                "type": "generic_project",
                "language": "Unknown",
                "framework": None
            }
        
        return {"detected": False}
    
    def _get_type_recommendation(self, project_info: Dict[str, Any]) -> str:
        """Get session type recommendation based on project info."""
        if not project_info["detected"]:
            return "Unable to determine project type. Consider using PROJECT type if this is a long-term project."
        
        proj_type = project_info["type"]
        
        if proj_type in ["node", "python", "java", "dotnet"]:
            return (
                f"Detected {project_info['language']} project. "
                "Recommend converting to PROJECT type for long-term development."
            )
        elif proj_type == "generic_project":
            return (
                "Detected project structure. "
                "Recommend converting to PROJECT type."
            )
        else:
            return "Consider EXPERIMENT type for testing or PROJECT type for development."
    
    async def update_session_metadata(
        self,
        session_id: UUID,
        updates: Dict[str, Any]
    ) -> bool:
        """
        Update session metadata.
        
        Args:
            session_id: Session to update
            updates: Metadata updates
            
        Returns:
            Success status
        """
        async with self._lock:
            session = self._sessions.get(session_id)
            
            if not session:
                return False
            
            # Update allowed fields
            allowed_fields = {
                "description", "tags", "project_type",
                "language", "framework", "custom_data"
            }
            
            for field, value in updates.items():
                if field in allowed_fields:
                    if field == "tags" and isinstance(value, list):
                        session.metadata.tags = set(value)
                    elif field == "custom_data" and isinstance(value, dict):
                        session.metadata.custom_data.update(value)
                    else:
                        setattr(session.metadata, field, value)
            
            # Save changes
            await self._session_store.save_session(session)
            
            logger.info(
                "Updated session metadata",
                session_id=str(session_id),
                fields=list(updates.keys())
            )
            
            return True
    
    async def get_session_metrics(self, session_id: UUID) -> Dict[str, Any]:
        """
        Get session usage metrics.
        
        Args:
            session_id: Session ID
            
        Returns:
            Session metrics
        """
        session = await self.get_session(session_id)
        
        if not session:
            return {"error": "Session not found"}
        
        metrics = {
            "session_id": str(session_id),
            "type": session.type.value,
            "state": session.state.value,
            "age_hours": session.age.total_seconds() / 3600,
            "idle_hours": session.idle_time.total_seconds() / 3600,
            "process_count": len(session.active_processes),
            "resource_usage": session.resource_usage,
        }
        
        # Get workspace size
        if self.workspace_manager:
            metrics["workspace_size_mb"] = (
                await self.workspace_manager.get_workspace_size(
                    session.workspace_path
                ) / (1024 * 1024)
            )
        
        # Get security metrics
        if self.security_manager:
            metrics["security_metrics"] = (
                await self.security_manager.get_session_resource_usage(
                    str(session_id)
                )
            )
        
        return metrics
    
    async def _cleanup_loop(self) -> None:
        """Background task for session cleanup."""
        while True:
            try:
                await asyncio.sleep(self._cleanup_interval.total_seconds())
                await self._cleanup_expired_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    "Error in cleanup loop",
                    error=str(e)
                )
    
    async def _cleanup_expired_sessions(self) -> None:
        """Clean up expired and idle sessions."""
        async with self._lock:
            cleaned = 0
            
            for session_id, session in list(self._sessions.items()):
                should_cleanup = False
                reason = ""
                
                # Check expiration
                if session.is_expired:
                    should_cleanup = True
                    reason = "expired"
                
                # Check idle timeout
                elif (self._session_idle_timeout and
                      session.idle_time > self._session_idle_timeout):
                    should_cleanup = True
                    reason = "idle timeout"
                
                # Clean up if needed
                if should_cleanup:
                    logger.info(
                        "Cleaning up session",
                        session_id=str(session_id),
                        reason=reason
                    )
                    
                    await self.delete_session(session_id, force=True)
                    cleaned += 1
            
            if cleaned > 0:
                logger.info(
                    "Cleaned up sessions",
                    count=cleaned
                )
    
    async def shutdown(self) -> None:
        """Shutdown session manager."""
        # Cancel cleanup task
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Save all sessions
        async with self._lock:
            for session in self._sessions.values():
                await self._session_store.save_session(session)
        
        logger.info("Session manager shutdown complete")