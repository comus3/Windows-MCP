"""
Session management tools for MCP Windows Development Server.

This module provides MCP tool implementations for session lifecycle management,
workspace operations, and session analysis.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
from uuid import UUID

from mcp.server.fastmcp import FastMCP, Context
from pydantic import BaseModel, Field

from ..core.session_manager import SessionManager
from ..models.session import SessionType, SessionMetadata, SessionPermissions, ResourceLimits
from ..utils.logging_config import get_logger

logger = get_logger(__name__)


# Tool parameter models
class CreateWorkspaceParams(BaseModel):
    """Parameters for create_workspace tool."""
    
    session_type: str = Field(
        default="temporary",
        description="Type of session: temporary, project, or experiment"
    )
    name: str = Field(
        description="Name for the workspace"
    )
    description: Optional[str] = Field(
        default=None,
        description="Description of the workspace purpose"
    )
    auto_cleanup_days: Optional[int] = Field(
        default=None,
        description="Days until automatic cleanup (overrides type default)"
    )
    tags: Optional[List[str]] = Field(
        default=None,
        description="Tags for categorizing the workspace"
    )


class ListWorkspacesParams(BaseModel):
    """Parameters for list_workspaces tool."""
    
    include_terminated: bool = Field(
        default=False,
        description="Include terminated workspaces"
    )
    filter_by_type: Optional[str] = Field(
        default=None,
        description="Filter by session type"
    )


class DeleteWorkspaceParams(BaseModel):
    """Parameters for delete_workspace tool."""
    
    session_id: str = Field(
        description="Session ID to delete"
    )
    confirm: bool = Field(
        default=False,
        description="Confirm deletion (required)"
    )
    force: bool = Field(
        default=False,
        description="Force deletion even if session is active"
    )


class ConvertSessionTypeParams(BaseModel):
    """Parameters for convert_session_type tool."""
    
    session_id: str = Field(
        description="Session ID to convert"
    )
    new_type: str = Field(
        description="New session type: temporary, project, or experiment"
    )
    name: Optional[str] = Field(
        default=None,
        description="New name for the session"
    )


class AnalyzeWorkspaceParams(BaseModel):
    """Parameters for analyze_workspace_for_project_type tool."""
    
    session_id: str = Field(
        description="Session ID to analyze"
    )


class UpdateSessionMetadataParams(BaseModel):
    """Parameters for update_session_metadata tool."""
    
    session_id: str = Field(
        description="Session ID to update"
    )
    description: Optional[str] = Field(
        default=None,
        description="New description"
    )
    tags: Optional[List[str]] = Field(
        default=None,
        description="New tags (replaces existing)"
    )
    project_type: Optional[str] = Field(
        default=None,
        description="Project type (e.g., python, node, java)"
    )
    language: Optional[str] = Field(
        default=None,
        description="Primary programming language"
    )
    framework: Optional[str] = Field(
        default=None,
        description="Framework being used"
    )
    custom_data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Custom metadata key-value pairs"
    )


class SessionTools:
    """MCP tools for session management."""
    
    def __init__(self, mcp: FastMCP, session_manager: SessionManager):
        """
        Initialize session tools.
        
        Args:
            mcp: FastMCP server instance
            session_manager: Session manager instance
        """
        self.mcp = mcp
        self.session_manager = session_manager
        
        # Register tools
        self._register_tools()
    
    def _register_tools(self) -> None:
        """Register all session tools with MCP."""
        
        @self.mcp.tool()
        async def create_workspace(
            session_type: str = "temporary",
            name: str = "Untitled",
            description: Optional[str] = None,
            auto_cleanup_days: Optional[int] = None,
            tags: Optional[List[str]] = None,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Create a new workspace for development.
            
            Creates an isolated workspace directory with appropriate permissions
            and initializes it with a default structure based on the session type.
            
            Args:
                session_type: Type of session - 'temporary' (1 day), 'experiment' (30 days), or 'project' (permanent)
                name: Name for the workspace
                description: Optional description of the workspace purpose
                auto_cleanup_days: Override automatic cleanup period in days
                tags: Optional tags for categorizing the workspace
                
            Returns:
                Dictionary containing session_id, workspace_path, and metadata
            """
            try:
                # Validate session type
                try:
                    session_type_enum = SessionType.from_string(session_type)
                except ValueError:
                    return {
                        "error": f"Invalid session type: {session_type}. "
                                f"Must be one of: temporary, experiment, project"
                    }
                
                # Create metadata
                metadata = SessionMetadata(
                    name=name,
                    description=description,
                    tags=set(tags) if tags else set()
                )
                
                # Create session
                session = await self.session_manager.create_session(
                    session_type=session_type_enum,
                    metadata=metadata,
                    auto_cleanup_days=auto_cleanup_days
                )
                
                logger.info(
                    "Created workspace via MCP",
                    session_id=str(session.id),
                    type=session_type,
                    name=name
                )
                
                return {
                    "session_id": str(session.id),
                    "workspace_path": str(session.workspace_path),
                    "type": session.type.value,
                    "name": session.metadata.name,
                    "description": session.metadata.description,
                    "tags": list(session.metadata.tags),
                    "created_at": session.created_at.isoformat(),
                    "expires_at": session.expires_at.isoformat() if session.expires_at else None,
                    "auto_cleanup": session.type.auto_cleanup,
                    "retention_days": session.type.default_retention_days
                }
                
            except Exception as e:
                logger.error(
                    "Failed to create workspace",
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def list_workspaces(
            include_terminated: bool = False,
            filter_by_type: Optional[str] = None,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            List all workspaces/sessions.
            
            Returns information about all workspaces including their paths,
            types, creation times, and current status.
            
            Args:
                include_terminated: Include terminated sessions in the list
                filter_by_type: Filter by session type (temporary, experiment, project)
                
            Returns:
                Dictionary containing list of workspace information
            """
            try:
                # Parse filter
                type_filter = None
                if filter_by_type:
                    try:
                        type_filter = SessionType.from_string(filter_by_type)
                    except ValueError:
                        return {
                            "error": f"Invalid session type filter: {filter_by_type}"
                        }
                
                # Get sessions
                summaries = await self.session_manager.list_sessions(
                    include_terminated=include_terminated,
                    session_type=type_filter
                )
                
                # Format results
                workspaces = []
                for summary in summaries:
                    workspaces.append({
                        "session_id": str(summary.id),
                        "name": summary.name,
                        "type": summary.type.value,
                        "state": summary.state.value,
                        "workspace_path": str(summary.workspace_path),
                        "created_at": summary.created_at.isoformat(),
                        "last_accessed_at": summary.last_accessed_at.isoformat(),
                        "age_hours": (datetime.utcnow() - summary.created_at).total_seconds() / 3600,
                        "idle_hours": (datetime.utcnow() - summary.last_accessed_at).total_seconds() / 3600
                    })
                
                return {
                    "workspaces": workspaces,
                    "total": len(workspaces),
                    "active": sum(1 for w in workspaces if w["state"] == "active"),
                    "filter": filter_by_type
                }
                
            except Exception as e:
                logger.error(
                    "Failed to list workspaces",
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def delete_workspace(
            session_id: str,
            confirm: bool = False,
            force: bool = False,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Delete a workspace and clean up resources.
            
            Terminates all processes, removes the workspace directory,
            and cleans up any associated resources.
            
            Args:
                session_id: ID of the session/workspace to delete
                confirm: Must be True to confirm deletion
                force: Force deletion even if session is active
                
            Returns:
                Dictionary with deletion status
            """
            try:
                if not confirm:
                    return {
                        "error": "Deletion not confirmed. Set confirm=true to delete."
                    }
                
                # Parse session ID
                try:
                    session_uuid = UUID(session_id)
                except ValueError:
                    return {"error": f"Invalid session ID: {session_id}"}
                
                # Get session info before deletion
                session = await self.session_manager.get_session(session_uuid)
                if not session:
                    return {"error": f"Session not found: {session_id}"}
                
                workspace_path = str(session.workspace_path)
                session_name = session.metadata.name
                
                # Delete session
                success = await self.session_manager.delete_session(
                    session_uuid,
                    force=force
                )
                
                if success:
                    logger.info(
                        "Deleted workspace via MCP",
                        session_id=session_id,
                        forced=force
                    )
                    
                    return {
                        "success": True,
                        "session_id": session_id,
                        "name": session_name,
                        "workspace_path": workspace_path,
                        "message": f"Successfully deleted workspace '{session_name}'"
                    }
                else:
                    return {
                        "success": False,
                        "error": "Failed to delete workspace. It may be in use or already deleted."
                    }
                    
            except Exception as e:
                logger.error(
                    "Failed to delete workspace",
                    session_id=session_id,
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def convert_session_type(
            session_id: str,
            new_type: str,
            name: Optional[str] = None,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Convert a session from one type to another.
            
            Useful for converting a temporary session to a project when you
            decide to keep working on it long-term.
            
            Args:
                session_id: ID of the session to convert
                new_type: New session type (temporary, experiment, project)
                name: Optional new name for the session
                
            Returns:
                Dictionary with conversion status and new session details
            """
            try:
                # Parse session ID
                try:
                    session_uuid = UUID(session_id)
                except ValueError:
                    return {"error": f"Invalid session ID: {session_id}"}
                
                # Parse new type
                try:
                    new_type_enum = SessionType.from_string(new_type)
                except ValueError:
                    return {
                        "error": f"Invalid session type: {new_type}. "
                                f"Must be one of: temporary, experiment, project"
                    }
                
                # Convert session
                success = await self.session_manager.convert_session_type(
                    session_uuid,
                    new_type_enum,
                    new_name=name
                )
                
                if success:
                    # Get updated session
                    session = await self.session_manager.get_session(session_uuid)
                    
                    logger.info(
                        "Converted session type via MCP",
                        session_id=session_id,
                        new_type=new_type
                    )
                    
                    return {
                        "success": True,
                        "session_id": session_id,
                        "old_type": session.type.value,  # Will show new type
                        "new_type": new_type,
                        "name": session.metadata.name,
                        "expires_at": session.expires_at.isoformat() if session.expires_at else None,
                        "message": f"Successfully converted to {new_type} session"
                    }
                else:
                    return {
                        "success": False,
                        "error": "Failed to convert session type"
                    }
                    
            except Exception as e:
                logger.error(
                    "Failed to convert session type",
                    session_id=session_id,
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def analyze_workspace_for_project_type(
            session_id: str,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Analyze a workspace to determine project type.
            
            Examines files and directory structure to identify the type of
            project (e.g., Python, Node.js, Java) and provides recommendations.
            
            Args:
                session_id: ID of the session to analyze
                
            Returns:
                Dictionary with analysis results and recommendations
            """
            try:
                # Parse session ID
                try:
                    session_uuid = UUID(session_id)
                except ValueError:
                    return {"error": f"Invalid session ID: {session_id}"}
                
                # Analyze workspace
                analysis = await self.session_manager.analyze_workspace_for_project_type(
                    session_uuid
                )
                
                if "error" in analysis:
                    return analysis
                
                logger.info(
                    "Analyzed workspace via MCP",
                    session_id=session_id,
                    detected=analysis.get("project_info", {}).get("detected", False)
                )
                
                return analysis
                
            except Exception as e:
                logger.error(
                    "Failed to analyze workspace",
                    session_id=session_id,
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def get_session_info(
            session_id: str,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Get detailed information about a session.
            
            Returns comprehensive information including metadata, resource usage,
            and current state.
            
            Args:
                session_id: ID of the session
                
            Returns:
                Dictionary with session information
            """
            try:
                # Parse session ID
                try:
                    session_uuid = UUID(session_id)
                except ValueError:
                    return {"error": f"Invalid session ID: {session_id}"}
                
                # Get session
                session = await self.session_manager.get_session(session_uuid)
                if not session:
                    return {"error": f"Session not found: {session_id}"}
                
                # Get metrics
                metrics = await self.session_manager.get_session_metrics(session_uuid)
                
                return {
                    "session_id": str(session.id),
                    "type": session.type.value,
                    "state": session.state.value,
                    "name": session.metadata.name,
                    "description": session.metadata.description,
                    "tags": list(session.metadata.tags),
                    "workspace_path": str(session.workspace_path),
                    "created_at": session.created_at.isoformat(),
                    "last_accessed_at": session.last_accessed_at.isoformat(),
                    "expires_at": session.expires_at.isoformat() if session.expires_at else None,
                    "metadata": {
                        "project_type": session.metadata.project_type,
                        "language": session.metadata.language,
                        "framework": session.metadata.framework,
                        "custom_data": session.metadata.custom_data
                    },
                    "metrics": metrics,
                    "permissions": {
                        "network_access": session.permissions.network_access,
                        "allowed_shells": list(session.permissions.allowed_shells),
                        "create_processes": session.permissions.create_processes
                    },
                    "resource_limits": {
                        "max_memory_mb": session.resource_limits.max_memory_mb,
                        "max_processes": session.resource_limits.max_processes,
                        "max_execution_time_seconds": session.resource_limits.max_execution_time_seconds,
                        "max_workspace_size_mb": session.resource_limits.max_workspace_size_mb
                    }
                }
                
            except Exception as e:
                logger.error(
                    "Failed to get session info",
                    session_id=session_id,
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def update_session_metadata(
            session_id: str,
            description: Optional[str] = None,
            tags: Optional[List[str]] = None,
            project_type: Optional[str] = None,
            language: Optional[str] = None,
            framework: Optional[str] = None,
            custom_data: Optional[Dict[str, Any]] = None,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Update session metadata.
            
            Updates descriptive information about a session without affecting
            its operational state.
            
            Args:
                session_id: ID of the session to update
                description: New description
                tags: New tags (replaces existing)
                project_type: Project type (e.g., python, node, java)
                language: Primary programming language
                framework: Framework being used
                custom_data: Custom metadata key-value pairs
                
            Returns:
                Dictionary with update status
            """
            try:
                # Parse session ID
                try:
                    session_uuid = UUID(session_id)
                except ValueError:
                    return {"error": f"Invalid session ID: {session_id}"}
                
                # Build updates
                updates = {}
                if description is not None:
                    updates["description"] = description
                if tags is not None:
                    updates["tags"] = tags
                if project_type is not None:
                    updates["project_type"] = project_type
                if language is not None:
                    updates["language"] = language
                if framework is not None:
                    updates["framework"] = framework
                if custom_data is not None:
                    updates["custom_data"] = custom_data
                
                if not updates:
                    return {"error": "No updates provided"}
                
                # Update metadata
                success = await self.session_manager.update_session_metadata(
                    session_uuid,
                    updates
                )
                
                if success:
                    logger.info(
                        "Updated session metadata via MCP",
                        session_id=session_id,
                        fields=list(updates.keys())
                    )
                    
                    return {
                        "success": True,
                        "session_id": session_id,
                        "updated_fields": list(updates.keys()),
                        "message": "Successfully updated session metadata"
                    }
                else:
                    return {
                        "success": False,
                        "error": "Failed to update session metadata"
                    }
                    
            except Exception as e:
                logger.error(
                    "Failed to update session metadata",
                    session_id=session_id,
                    error=str(e)
                )
                return {"error": str(e)}