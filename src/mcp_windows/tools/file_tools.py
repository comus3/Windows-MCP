"""
File management tools for MCP Windows Development Server.

This module provides MCP tool implementations for file operations including
reading, writing, listing, and managing files within authorized workspaces.
"""

import os
import shutil
import aiofiles
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from uuid import UUID
import base64
import mimetypes

from fastmcp import FastMCP, Context
from pydantic import BaseModel, Field

from ..core.session_manager import SessionManager
from ..core.security_manager import SecurityManager
from ..models.registry_entry import PermissionLevel
from ..models.file_info import FileInfo, FileType
from ..utils.path_utils import PathUtils
from ..utils.logging_config import get_logger, AuditLogger

logger = get_logger(__name__)


# Tool parameter models
class ReadFileParams(BaseModel):
    """Parameters for read_file tool."""
    
    file_path: str = Field(
        description="Path to the file to read"
    )
    session_id: str = Field(
        description="Session ID for access context"
    )
    encoding: str = Field(
        default="utf-8",
        description="Text encoding (e.g., utf-8, cp1252)"
    )
    as_base64: bool = Field(
        default=False,
        description="Return content as base64 for binary files"
    )


class WriteFileParams(BaseModel):
    """Parameters for write_file tool."""
    
    file_path: str = Field(
        description="Path where to write the file"
    )
    content: str = Field(
        description="Content to write (text or base64)"
    )
    session_id: str = Field(
        description="Session ID for access context"
    )
    encoding: str = Field(
        default="utf-8",
        description="Text encoding for text files"
    )
    is_base64: bool = Field(
        default=False,
        description="Whether content is base64 encoded"
    )
    create_backup: bool = Field(
        default=True,
        description="Create backup if file exists"
    )
    create_directories: bool = Field(
        default=True,
        description="Create parent directories if needed"
    )


class ListDirectoryParams(BaseModel):
    """Parameters for list_directory tool."""
    
    path: str = Field(
        description="Directory path to list"
    )
    session_id: str = Field(
        description="Session ID for access context"
    )
    recursive: bool = Field(
        default=False,
        description="List recursively"
    )
    include_hidden: bool = Field(
        default=False,
        description="Include hidden files"
    )
    pattern: Optional[str] = Field(
        default=None,
        description="Filter pattern (e.g., *.py)"
    )


class FileTools:
    """MCP tools for file management."""
    
    def __init__(
        self,
        mcp: FastMCP,
        session_manager: SessionManager,
        security_manager: Optional[SecurityManager] = None
    ):
        """
        Initialize file tools.
        
        Args:
            mcp: FastMCP server instance
            session_manager: Session manager instance
            security_manager: Optional security manager
        """
        self.mcp = mcp
        self.session_manager = session_manager
        self.security_manager = security_manager
        
        # Audit logger
        self._audit_logger = AuditLogger(
            session_manager.settings.workspace.root_directory / ".audit" / "files.log"
        )
        
        # Register tools
        self._register_tools()
    
    def _register_tools(self) -> None:
        """Register all file tools with MCP."""
        
        @self.mcp.tool()
        async def read_file(
            file_path: str,
            session_id: str,
            encoding: str = "utf-8",
            as_base64: bool = False,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Read contents of a file.
            
            Reads a file from the workspace or authorized directories with
            proper security validation.
            
            Args:
                file_path: Path to the file to read
                session_id: Session ID for access context
                encoding: Text encoding (default: utf-8)
                as_base64: Return content as base64 for binary files
                
            Returns:
                Dictionary with file content and metadata
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
                
                # Parse and validate path
                path = Path(file_path)
                if not path.is_absolute():
                    # Make relative to workspace
                    path = session.workspace_path / path
                
                path = path.resolve()
                
                # Check security
                if self.security_manager:
                    allowed, reason = await self.security_manager.validate_path_access(
                        path,
                        session,
                        PermissionLevel.READ_ONLY,
                        "read_file"
                    )
                    if not allowed:
                        return {"error": f"Access denied: {reason}"}
                
                # Check file exists
                if not path.exists():
                    return {"error": f"File not found: {file_path}"}
                
                if not path.is_file():
                    return {"error": f"Not a file: {file_path}"}
                
                # Get file info
                file_info = FileInfo.from_path(path)
                
                # Read file
                try:
                    if as_base64 or file_info.is_binary_file:
                        # Read as binary
                        async with aiofiles.open(path, 'rb') as f:
                            content = await f.read()
                        
                        content_str = base64.b64encode(content).decode('ascii')
                        is_base64 = True
                    else:
                        # Read as text
                        async with aiofiles.open(path, 'r', encoding=encoding) as f:
                            content_str = await f.read()
                        is_base64 = False
                        
                except UnicodeDecodeError:
                    # Fallback to binary if text decode fails
                    async with aiofiles.open(path, 'rb') as f:
                        content = await f.read()
                    content_str = base64.b64encode(content).decode('ascii')
                    is_base64 = True
                
                # Audit log
                self._audit_logger.log_file_operation(
                    str(session_uuid),
                    "read",
                    str(path),
                    True,
                    file_info.size
                )
                
                logger.info(
                    "Read file via MCP",
                    session_id=session_id,
                    path=str(path),
                    size=file_info.size
                )
                
                return {
                    "content": content_str,
                    "is_base64": is_base64,
                    "encoding": encoding if not is_base64 else None,
                    "path": str(path),
                    "size": file_info.size,
                    "mime_type": file_info.mime_type,
                    "created_at": file_info.created_at.isoformat(),
                    "modified_at": file_info.modified_at.isoformat(),
                    "is_readonly": file_info.is_readonly
                }
                
            except Exception as e:
                logger.error(
                    "Failed to read file",
                    path=file_path,
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def write_file(
            file_path: str,
            content: str,
            session_id: str,
            encoding: str = "utf-8",
            is_base64: bool = False,
            create_backup: bool = True,
            create_directories: bool = True,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Write content to a file.
            
            Creates or overwrites a file with the provided content. Supports
            both text and binary (base64) content.
            
            Args:
                file_path: Path where to write the file
                content: Content to write (text or base64)
                session_id: Session ID for access context
                encoding: Text encoding for text files
                is_base64: Whether content is base64 encoded
                create_backup: Create backup if file exists
                create_directories: Create parent directories if needed
                
            Returns:
                Dictionary with write operation status
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
                
                # Parse and validate path
                path = Path(file_path)
                if not path.is_absolute():
                    # Make relative to workspace
                    path = session.workspace_path / path
                
                path = path.resolve()
                
                # Check security
                if self.security_manager:
                    allowed, reason = await self.security_manager.validate_path_access(
                        path,
                        session,
                        PermissionLevel.READ_WRITE,
                        "write_file"
                    )
                    if not allowed:
                        return {"error": f"Access denied: {reason}"}
                
                # Create parent directories if needed
                if create_directories and not path.parent.exists():
                    path.parent.mkdir(parents=True, exist_ok=True)
                
                # Create backup if file exists
                backup_path = None
                if create_backup and path.exists():
                    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                    backup_path = path.with_suffix(f".backup_{timestamp}{path.suffix}")
                    shutil.copy2(path, backup_path)
                
                # Prepare content
                if is_base64:
                    # Decode base64
                    try:
                        content_bytes = base64.b64decode(content)
                    except Exception:
                        return {"error": "Invalid base64 content"}
                    
                    # Write binary
                    async with aiofiles.open(path, 'wb') as f:
                        await f.write(content_bytes)
                    
                    written_size = len(content_bytes)
                else:
                    # Write text
                    async with aiofiles.open(path, 'w', encoding=encoding) as f:
                        await f.write(content)
                    
                    written_size = len(content.encode(encoding))
                
                # Audit log
                self._audit_logger.log_file_operation(
                    str(session_uuid),
                    "write",
                    str(path),
                    True,
                    written_size
                )
                
                logger.info(
                    "Wrote file via MCP",
                    session_id=session_id,
                    path=str(path),
                    size=written_size,
                    backup=backup_path is not None
                )
                
                return {
                    "success": True,
                    "path": str(path),
                    "size": written_size,
                    "backup_path": str(backup_path) if backup_path else None,
                    "encoding": encoding if not is_base64 else None,
                    "message": f"Successfully wrote {written_size} bytes to {path.name}"
                }
                
            except Exception as e:
                logger.error(
                    "Failed to write file",
                    path=file_path,
                    error=str(e)
                )
                
                # Audit log failure
                self._audit_logger.log_file_operation(
                    str(session_uuid) if 'session_uuid' in locals() else "unknown",
                    "write",
                    file_path,
                    False,
                    None
                )
                
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def list_directory(
            path: str,
            session_id: str,
            recursive: bool = False,
            include_hidden: bool = False,
            pattern: Optional[str] = None,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            List contents of a directory.
            
            Lists files and subdirectories with optional filtering and
            recursive traversal.
            
            Args:
                path: Directory path to list
                session_id: Session ID for access context
                recursive: List recursively
                include_hidden: Include hidden files
                pattern: Filter pattern (e.g., *.py)
                
            Returns:
                Dictionary with directory listing
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
                
                # Parse and validate path
                dir_path = Path(path)
                if not dir_path.is_absolute():
                    # Make relative to workspace
                    dir_path = session.workspace_path / dir_path
                
                dir_path = dir_path.resolve()
                
                # Check security
                if self.security_manager:
                    allowed, reason = await self.security_manager.validate_path_access(
                        dir_path,
                        session,
                        PermissionLevel.READ_ONLY,
                        "list_directory"
                    )
                    if not allowed:
                        return {"error": f"Access denied: {reason}"}
                
                # Check directory exists
                if not dir_path.exists():
                    return {"error": f"Directory not found: {path}"}
                
                if not dir_path.is_dir():
                    return {"error": f"Not a directory: {path}"}
                
                # List directory
                items = []
                total_size = 0
                
                if recursive:
                    # Recursive listing
                    for item in dir_path.rglob(pattern or "*"):
                        if not include_hidden and item.name.startswith('.'):
                            continue
                        
                        try:
                            rel_path = item.relative_to(dir_path)
                            file_info = FileInfo.from_path(item)
                            
                            items.append({
                                "name": item.name,
                                "path": str(item),
                                "relative_path": str(rel_path),
                                "type": file_info.type.value,
                                "size": file_info.size,
                                "modified_at": file_info.modified_at.isoformat(),
                                "is_hidden": file_info.is_hidden
                            })
                            
                            if file_info.type == FileType.FILE:
                                total_size += file_info.size
                                
                        except Exception as e:
                            logger.debug(f"Failed to get info for {item}: {e}")
                else:
                    # Non-recursive listing
                    import fnmatch
                    
                    for item in dir_path.iterdir():
                        if not include_hidden and item.name.startswith('.'):
                            continue
                        
                        if pattern and not fnmatch.fnmatch(item.name, pattern):
                            continue
                        
                        try:
                            file_info = FileInfo.from_path(item)
                            
                            items.append({
                                "name": item.name,
                                "path": str(item),
                                "type": file_info.type.value,
                                "size": file_info.size,
                                "modified_at": file_info.modified_at.isoformat(),
                                "is_hidden": file_info.is_hidden
                            })
                            
                            if file_info.type == FileType.FILE:
                                total_size += file_info.size
                                
                        except Exception as e:
                            logger.debug(f"Failed to get info for {item}: {e}")
                
                # Sort items (directories first, then by name)
                items.sort(key=lambda x: (x["type"] != "directory", x["name"].lower()))
                
                logger.info(
                    "Listed directory via MCP",
                    session_id=session_id,
                    path=str(dir_path),
                    items=len(items),
                    recursive=recursive
                )
                
                return {
                    "path": str(dir_path),
                    "items": items,
                    "total_items": len(items),
                    "total_size": total_size,
                    "file_count": sum(1 for i in items if i["type"] == "file"),
                    "directory_count": sum(1 for i in items if i["type"] == "directory"),
                    "recursive": recursive,
                    "pattern": pattern
                }
                
            except Exception as e:
                logger.error(
                    "Failed to list directory",
                    path=path,
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def copy_file(
            source_path: str,
            dest_path: str,
            session_id: str,
            overwrite: bool = False,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Copy a file to a new location.
            
            Copies a file within the workspace or between authorized directories.
            
            Args:
                source_path: Source file path
                dest_path: Destination path
                session_id: Session ID for access context
                overwrite: Overwrite if destination exists
                
            Returns:
                Dictionary with copy operation status
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
                
                # Parse paths
                src = Path(source_path)
                dst = Path(dest_path)
                
                if not src.is_absolute():
                    src = session.workspace_path / src
                if not dst.is_absolute():
                    dst = session.workspace_path / dst
                
                src = src.resolve()
                dst = dst.resolve()
                
                # Check security for source
                if self.security_manager:
                    allowed, reason = await self.security_manager.validate_path_access(
                        src,
                        session,
                        PermissionLevel.READ_ONLY,
                        "copy_source"
                    )
                    if not allowed:
                        return {"error": f"Access denied for source: {reason}"}
                
                # Check security for destination
                if self.security_manager:
                    allowed, reason = await self.security_manager.validate_path_access(
                        dst.parent if dst.exists() else dst,
                        session,
                        PermissionLevel.READ_WRITE,
                        "copy_dest"
                    )
                    if not allowed:
                        return {"error": f"Access denied for destination: {reason}"}
                
                # Check source exists
                if not src.exists():
                    return {"error": f"Source file not found: {source_path}"}
                
                if not src.is_file():
                    return {"error": f"Source is not a file: {source_path}"}
                
                # Check destination
                if dst.exists() and not overwrite:
                    return {"error": f"Destination already exists: {dest_path}"}
                
                # Create destination directory if needed
                dst.parent.mkdir(parents=True, exist_ok=True)
                
                # Copy file
                shutil.copy2(src, dst)
                
                # Get file info
                file_info = FileInfo.from_path(dst)
                
                # Audit log
                self._audit_logger.log_file_operation(
                    str(session_uuid),
                    "copy",
                    f"{src} -> {dst}",
                    True,
                    file_info.size
                )
                
                logger.info(
                    "Copied file via MCP",
                    session_id=session_id,
                    source=str(src),
                    dest=str(dst)
                )
                
                return {
                    "success": True,
                    "source_path": str(src),
                    "dest_path": str(dst),
                    "size": file_info.size,
                    "message": f"Successfully copied {src.name} to {dst}"
                }
                
            except Exception as e:
                logger.error(
                    "Failed to copy file",
                    source=source_path,
                    dest=dest_path,
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def move_file(
            source_path: str,
            dest_path: str,
            session_id: str,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Move or rename a file.
            
            Moves a file to a new location or renames it within the same directory.
            
            Args:
                source_path: Source file path
                dest_path: Destination path
                session_id: Session ID for access context
                
            Returns:
                Dictionary with move operation status
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
                
                # Parse paths
                src = Path(source_path)
                dst = Path(dest_path)
                
                if not src.is_absolute():
                    src = session.workspace_path / src
                if not dst.is_absolute():
                    dst = session.workspace_path / dst
                
                src = src.resolve()
                dst = dst.resolve()
                
                # Check security for source
                if self.security_manager:
                    allowed, reason = await self.security_manager.validate_path_access(
                        src,
                        session,
                        PermissionLevel.READ_WRITE,
                        "move_source"
                    )
                    if not allowed:
                        return {"error": f"Access denied for source: {reason}"}
                
                # Check security for destination
                if self.security_manager:
                    allowed, reason = await self.security_manager.validate_path_access(
                        dst.parent if dst.exists() else dst,
                        session,
                        PermissionLevel.READ_WRITE,
                        "move_dest"
                    )
                    if not allowed:
                        return {"error": f"Access denied for destination: {reason}"}
                
                # Check source exists
                if not src.exists():
                    return {"error": f"Source file not found: {source_path}"}
                
                # Check destination doesn't exist
                if dst.exists():
                    return {"error": f"Destination already exists: {dest_path}"}
                
                # Create destination directory if needed
                dst.parent.mkdir(parents=True, exist_ok=True)
                
                # Move file
                shutil.move(str(src), str(dst))
                
                # Audit log
                self._audit_logger.log_file_operation(
                    str(session_uuid),
                    "move",
                    f"{src} -> {dst}",
                    True,
                    None
                )
                
                logger.info(
                    "Moved file via MCP",
                    session_id=session_id,
                    source=str(src),
                    dest=str(dst)
                )
                
                return {
                    "success": True,
                    "source_path": str(src),
                    "dest_path": str(dst),
                    "message": f"Successfully moved {src.name} to {dst}"
                }
                
            except Exception as e:
                logger.error(
                    "Failed to move file",
                    source=source_path,
                    dest=dest_path,
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def delete_file(
            file_path: str,
            session_id: str,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Delete a file.
            
            Permanently deletes a file from the workspace.
            
            Args:
                file_path: Path to the file to delete
                session_id: Session ID for access context
                
            Returns:
                Dictionary with deletion status
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
                
                # Parse path
                path = Path(file_path)
                if not path.is_absolute():
                    path = session.workspace_path / path
                
                path = path.resolve()
                
                # Check security
                if self.security_manager:
                    allowed, reason = await self.security_manager.validate_path_access(
                        path,
                        session,
                        PermissionLevel.READ_WRITE,
                        "delete_file"
                    )
                    if not allowed:
                        return {"error": f"Access denied: {reason}"}
                
                # Check file exists
                if not path.exists():
                    return {"error": f"File not found: {file_path}"}
                
                if not path.is_file():
                    return {"error": f"Not a file: {file_path}"}
                
                # Get size before deletion
                size = path.stat().st_size
                
                # Delete file
                path.unlink()
                
                # Audit log
                self._audit_logger.log_file_operation(
                    str(session_uuid),
                    "delete",
                    str(path),
                    True,
                    size
                )
                
                logger.info(
                    "Deleted file via MCP",
                    session_id=session_id,
                    path=str(path),
                    size=size
                )
                
                return {
                    "success": True,
                    "path": str(path),
                    "size": size,
                    "message": f"Successfully deleted {path.name}"
                }
                
            except Exception as e:
                logger.error(
                    "Failed to delete file",
                    path=file_path,
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def create_directory(
            directory_path: str,
            session_id: str,
            create_parents: bool = True,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Create a directory.
            
            Creates a new directory in the workspace.
            
            Args:
                directory_path: Path for the new directory
                session_id: Session ID for access context
                create_parents: Create parent directories if needed
                
            Returns:
                Dictionary with creation status
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
                
                # Parse path
                path = Path(directory_path)
                if not path.is_absolute():
                    path = session.workspace_path / path
                
                path = path.resolve()
                
                # Check security
                if self.security_manager:
                    # Check parent directory access
                    allowed, reason = await self.security_manager.validate_path_access(
                        path.parent if path.parent.exists() else path,
                        session,
                        PermissionLevel.READ_WRITE,
                        "create_directory"
                    )
                    if not allowed:
                        return {"error": f"Access denied: {reason}"}
                
                # Check if already exists
                if path.exists():
                    if path.is_dir():
                        return {
                            "success": True,
                            "path": str(path),
                            "message": "Directory already exists",
                            "created": False
                        }
                    else:
                        return {"error": f"Path exists but is not a directory: {directory_path}"}
                
                # Create directory
                path.mkdir(parents=create_parents, exist_ok=True)
                
                # Audit log
                self._audit_logger.log_file_operation(
                    str(session_uuid),
                    "create_directory",
                    str(path),
                    True,
                    None
                )
                
                logger.info(
                    "Created directory via MCP",
                    session_id=session_id,
                    path=str(path)
                )
                
                return {
                    "success": True,
                    "path": str(path),
                    "message": f"Successfully created directory {path.name}",
                    "created": True
                }
                
            except Exception as e:
                logger.error(
                    "Failed to create directory",
                    path=directory_path,
                    error=str(e)
                )
                return {"error": str(e)}
        
        @self.mcp.tool()
        async def get_file_info(
            file_path: str,
            session_id: str,
            calculate_hash: bool = False,
            ctx: Context = None
        ) -> Dict[str, Any]:
            """
            Get detailed information about a file.
            
            Returns metadata including size, timestamps, permissions, and
            optionally file hashes.
            
            Args:
                file_path: Path to the file
                session_id: Session ID for access context
                calculate_hash: Calculate MD5 and SHA256 hashes
                
            Returns:
                Dictionary with file information
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
                
                # Parse path
                path = Path(file_path)
                if not path.is_absolute():
                    path = session.workspace_path / path
                
                path = path.resolve()
                
                # Check security
                if self.security_manager:
                    allowed, reason = await self.security_manager.validate_path_access(
                        path,
                        session,
                        PermissionLevel.READ_ONLY,
                        "get_file_info"
                    )
                    if not allowed:
                        return {"error": f"Access denied: {reason}"}
                
                # Check exists
                if not path.exists():
                    return {"error": f"Path not found: {file_path}"}
                
                # Get file info
                file_info = FileInfo.from_path(path, calculate_hash=calculate_hash)
                
                logger.info(
                    "Got file info via MCP",
                    session_id=session_id,
                    path=str(path)
                )
                
                return file_info.to_dict(include_content=True)
                
            except Exception as e:
                logger.error(
                    "Failed to get file info",
                    path=file_path,
                    error=str(e)
                )
                return {"error": str(e)}