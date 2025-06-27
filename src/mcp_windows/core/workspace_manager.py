"""
Workspace manager for MCP Windows Development Server.

This module handles workspace creation, management, junction points,
and workspace analysis operations.
"""

import os
import shutil
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime
import json
import hashlib

import aiofiles
import aioshutil
import structlog

from ..config.settings import WorkspaceSettings
from ..models.session import SessionType
from ..models.file_info import FileInfo, DirectoryListing, FileType
from ..utils.path_utils import PathUtils
from ..utils.logging_config import get_logger, AuditLogger
from ..registry.folder_registry import FolderRegistry

logger = get_logger(__name__)


class WorkspaceStructure:
    """Manages workspace directory structure."""
    
    # Default directories by session type
    DEFAULT_STRUCTURES = {
        SessionType.TEMPORARY: [
            "temp",
            "output"
        ],
        SessionType.EXPERIMENT: [
            "src",
            "data",
            "output",
            "notebooks"
        ],
        SessionType.PROJECT: [
            "src",
            "tests",
            "docs",
            "data",
            "scripts",
            "config",
            ".vscode"
        ]
    }
    
    # Common project files
    COMMON_FILES = {
        "README.md": "# {name}\n\nCreated: {date}\nType: {type}\n\n## Description\n\n{description}\n",
        ".gitignore": "# Python\n__pycache__/\n*.py[cod]\n.env\nvenv/\n\n# Output\noutput/\n*.log\n",
    }
    
    @staticmethod
    async def create_structure(
        workspace_path: Path,
        session_type: SessionType,
        session_name: str,
        custom_dirs: Optional[List[str]] = None
    ) -> List[Path]:
        """
        Create workspace directory structure.
        
        Args:
            workspace_path: Root workspace path
            session_type: Type of session
            session_name: Session name
            custom_dirs: Custom directories to create
            
        Returns:
            List of created directories
        """
        created = []
        
        # Get directories to create
        dirs = custom_dirs or WorkspaceStructure.DEFAULT_STRUCTURES.get(
            session_type, []
        )
        
        # Create directories
        for dir_name in dirs:
            dir_path = workspace_path / dir_name
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                created.append(dir_path)
            except Exception as e:
                logger.error(f"Failed to create directory {dir_path}: {e}")
        
        # Create common files
        for filename, template in WorkspaceStructure.COMMON_FILES.items():
            file_path = workspace_path / filename
            try:
                if not file_path.exists():
                    content = template.format(
                        name=session_name,
                        date=datetime.utcnow().isoformat(),
                        type=session_type.value,
                        description=""
                    )
                    async with aiofiles.open(file_path, 'w') as f:
                        await f.write(content)
            except Exception as e:
                logger.error(f"Failed to create file {file_path}: {e}")
        
        return created


class WorkspaceManager:
    """
    Manages workspace operations for MCP Windows server.
    
    This class handles:
    - Workspace creation and deletion
    - Junction point management
    - Workspace analysis and metrics
    - Directory structure initialization
    - Cleanup operations
    """
    
    def __init__(
        self,
        settings: WorkspaceSettings,
        folder_registry: Optional[FolderRegistry] = None
    ):
        """
        Initialize workspace manager.
        
        Args:
            settings: Workspace configuration settings
            folder_registry: Folder authorization registry
        """
        self.settings = settings
        self.folder_registry = folder_registry
        
        # Ensure root directory exists
        self.root_directory = settings.root_directory
        self.root_directory.mkdir(parents=True, exist_ok=True)
        
        # Temp directory
        self.temp_directory = settings.temp_directory or (self.root_directory / ".temp")
        self.temp_directory.mkdir(parents=True, exist_ok=True)
        
        # Audit logger
        self._audit_logger = AuditLogger(
            self.root_directory / ".audit" / "workspaces.log"
        )
        
        # Workspace tracking
        self._active_workspaces: Set[Path] = set()
        self._lock = asyncio.Lock()
        
        logger.info(
            "Workspace manager initialized",
            root=str(self.root_directory),
            temp=str(self.temp_directory)
        )
    
    async def create_workspace(
        self,
        session_type: SessionType,
        session_name: str,
        workspace_id: Optional[str] = None
    ) -> Path:
        """
        Create a new workspace directory.
        
        Args:
            session_type: Type of session
            session_name: Name for the workspace
            workspace_id: Optional specific workspace ID
            
        Returns:
            Path to created workspace
        """
        async with self._lock:
            # Generate workspace ID
            if not workspace_id:
                workspace_id = self._generate_workspace_id(session_name)
            
            # Determine parent directory
            if session_type == SessionType.TEMPORARY:
                parent = self.temp_directory
            else:
                parent = self.root_directory / session_type.value
            
            parent.mkdir(parents=True, exist_ok=True)
            
            # Create workspace directory
            workspace_path = parent / workspace_id
            
            # Ensure unique path
            workspace_path = PathUtils.get_unique_path(workspace_path)
            
            # Create directory
            workspace_path.mkdir(parents=True, exist_ok=True)
            
            # Track workspace
            self._active_workspaces.add(workspace_path)
            
            # Create metadata file
            metadata = {
                "id": workspace_id,
                "name": session_name,
                "type": session_type.value,
                "created_at": datetime.utcnow().isoformat(),
                "path": str(workspace_path)
            }
            
            metadata_file = workspace_path / ".mcp_workspace"
            async with aiofiles.open(metadata_file, 'w') as f:
                await f.write(json.dumps(metadata, indent=2))
            
            # Set hidden attribute on metadata file
            try:
                import win32file
                win32file.SetFileAttributes(
                    str(metadata_file),
                    win32file.FILE_ATTRIBUTE_HIDDEN
                )
            except Exception:
                pass
            
            logger.info(
                "Created workspace",
                path=str(workspace_path),
                type=session_type.value,
                name=session_name
            )
            
            return workspace_path
    
    async def initialize_workspace_structure(
        self,
        workspace_path: Path,
        create_defaults: bool = True,
        custom_dirs: Optional[List[str]] = None
    ) -> None:
        """
        Initialize workspace directory structure.
        
        Args:
            workspace_path: Workspace root path
            create_defaults: Create default structure
            custom_dirs: Additional directories to create
        """
        # Get workspace metadata
        metadata = await self._read_workspace_metadata(workspace_path)
        session_type = SessionType(metadata.get("type", "temporary"))
        session_name = metadata.get("name", "Workspace")
        
        # Create structure
        if create_defaults:
            await WorkspaceStructure.create_structure(
                workspace_path,
                session_type,
                session_name,
                custom_dirs
            )
        elif custom_dirs:
            for dir_name in custom_dirs:
                dir_path = workspace_path / dir_name
                dir_path.mkdir(parents=True, exist_ok=True)
    
    async def create_junction_points(
        self,
        workspace_path: Path,
        authorized_folders: List[Tuple[str, Path]]
    ) -> List[Path]:
        """
        Create junction points to authorized folders.
        
        Args:
            workspace_path: Workspace root path
            authorized_folders: List of (name, target_path) tuples
            
        Returns:
            List of created junction paths
        """
        junctions = []
        links_dir = workspace_path / ".links"
        links_dir.mkdir(exist_ok=True)
        
        # Hide links directory
        try:
            import win32file
            win32file.SetFileAttributes(
                str(links_dir),
                win32file.FILE_ATTRIBUTE_HIDDEN
            )
        except Exception:
            pass
        
        for name, target_path in authorized_folders:
            # Validate target
            if not target_path.exists() or not target_path.is_dir():
                logger.warning(
                    "Skipping invalid junction target",
                    name=name,
                    target=str(target_path)
                )
                continue
            
            # Create junction
            junction_path = links_dir / PathUtils.sanitize_filename(name)
            
            if PathUtils.create_junction(junction_path, target_path):
                junctions.append(junction_path)
                logger.debug(
                    "Created junction point",
                    junction=str(junction_path),
                    target=str(target_path)
                )
            else:
                logger.error(
                    "Failed to create junction",
                    junction=str(junction_path),
                    target=str(target_path)
                )
        
        return junctions
    
    async def delete_workspace(
        self,
        workspace_path: Path,
        force: bool = False,
        archive: bool = False
    ) -> bool:
        """
        Delete or archive a workspace.
        
        Args:
            workspace_path: Workspace to delete
            force: Force deletion of read-only files
            archive: Archive instead of delete
            
        Returns:
            Success status
        """
        async with self._lock:
            try:
                # Validate workspace
                if not await self._is_valid_workspace(workspace_path):
                    logger.warning(
                        "Attempted to delete invalid workspace",
                        path=str(workspace_path)
                    )
                    return False
                
                # Archive if requested
                if archive:
                    return await self._archive_workspace(workspace_path)
                
                # Remove junctions first
                links_dir = workspace_path / ".links"
                if links_dir.exists():
                    for junction in links_dir.iterdir():
                        if PathUtils.is_junction(junction):
                            junction.rmdir()
                
                # Delete workspace
                success = await aioshutil.rmtree(
                    str(workspace_path),
                    ignore_errors=force
                )
                
                # Remove from tracking
                self._active_workspaces.discard(workspace_path)
                
                # Audit log
                self._audit_logger.log_file_operation(
                    "workspace",
                    "delete",
                    str(workspace_path),
                    True,
                    None
                )
                
                logger.info(
                    "Deleted workspace",
                    path=str(workspace_path),
                    forced=force
                )
                
                return True
                
            except Exception as e:
                logger.error(
                    "Failed to delete workspace",
                    path=str(workspace_path),
                    error=str(e)
                )
                return False
    
    async def get_workspace_size(self, workspace_path: Path) -> int:
        """
        Calculate total size of workspace.
        
        Args:
            workspace_path: Workspace path
            
        Returns:
            Total size in bytes
        """
        try:
            return await asyncio.to_thread(
                PathUtils.calculate_directory_size,
                workspace_path,
                follow_symlinks=False
            )
        except Exception as e:
            logger.error(
                "Failed to calculate workspace size",
                path=str(workspace_path),
                error=str(e)
            )
            return 0
    
    async def analyze_workspace(self, workspace_path: Path) -> Dict[str, Any]:
        """
        Analyze workspace contents and structure.
        
        Args:
            workspace_path: Workspace to analyze
            
        Returns:
            Analysis results
        """
        analysis = {
            "path": str(workspace_path),
            "exists": workspace_path.exists(),
            "size_bytes": 0,
            "file_count": 0,
            "directory_count": 0,
            "files": {},
            "directories": [],
            "file_types": {},
            "largest_files": [],
            "metadata": {}
        }
        
        if not workspace_path.exists():
            return analysis
        
        # Read metadata
        analysis["metadata"] = await self._read_workspace_metadata(workspace_path)
        
        # Analyze contents
        try:
            file_sizes = []
            
            for item in workspace_path.rglob("*"):
                # Skip hidden/system directories
                if any(part.startswith('.') for part in item.parts[len(workspace_path.parts):]):
                    continue
                
                if item.is_file():
                    size = item.stat().st_size
                    analysis["file_count"] += 1
                    analysis["size_bytes"] += size
                    
                    # Track file types
                    ext = item.suffix.lower()
                    analysis["file_types"][ext] = analysis["file_types"].get(ext, 0) + 1
                    
                    # Track files by name
                    rel_path = item.relative_to(workspace_path)
                    analysis["files"][str(rel_path)] = size
                    
                    # Track for largest files
                    file_sizes.append((size, str(rel_path)))
                    
                elif item.is_dir():
                    analysis["directory_count"] += 1
                    rel_path = item.relative_to(workspace_path)
                    analysis["directories"].append(str(rel_path))
            
            # Get largest files
            file_sizes.sort(reverse=True)
            analysis["largest_files"] = [
                {"path": path, "size": size}
                for size, path in file_sizes[:10]
            ]
            
        except Exception as e:
            logger.error(
                "Failed to analyze workspace",
                path=str(workspace_path),
                error=str(e)
            )
        
        return analysis
    
    async def list_workspaces(
        self,
        session_type: Optional[SessionType] = None,
        include_metadata: bool = True
    ) -> List[Dict[str, Any]]:
        """
        List all workspaces.
        
        Args:
            session_type: Filter by session type
            include_metadata: Include workspace metadata
            
        Returns:
            List of workspace information
        """
        workspaces = []
        
        # Search in root and temp directories
        search_dirs = [self.root_directory]
        if self.temp_directory != self.root_directory:
            search_dirs.append(self.temp_directory)
        
        for search_dir in search_dirs:
            for item in search_dir.rglob(".mcp_workspace"):
                workspace_path = item.parent
                
                # Read metadata
                if include_metadata:
                    metadata = await self._read_workspace_metadata(workspace_path)
                else:
                    metadata = {}
                
                # Filter by type
                if session_type and metadata.get("type") != session_type.value:
                    continue
                
                # Get basic info
                info = {
                    "path": str(workspace_path),
                    "name": workspace_path.name,
                    "metadata": metadata,
                    "size_bytes": await self.get_workspace_size(workspace_path),
                    "active": workspace_path in self._active_workspaces
                }
                
                workspaces.append(info)
        
        return sorted(workspaces, key=lambda w: w.get("metadata", {}).get("created_at", ""), reverse=True)
    
    async def cleanup_old_workspaces(
        self,
        max_age_days: Optional[int] = None,
        dry_run: bool = False
    ) -> List[Path]:
        """
        Clean up old workspaces.
        
        Args:
            max_age_days: Maximum age in days
            dry_run: Only report what would be deleted
            
        Returns:
            List of cleaned workspace paths
        """
        cleaned = []
        
        # Use settings if max age not specified
        if max_age_days is None:
            max_age_days = {
                SessionType.TEMPORARY: self.settings.temporary_retention_hours / 24,
                SessionType.EXPERIMENT: self.settings.experiment_retention_days,
            }
        else:
            max_age_days = {t: max_age_days for t in SessionType}
        
        workspaces = await self.list_workspaces(include_metadata=True)
        
        for workspace in workspaces:
            metadata = workspace.get("metadata", {})
            created_str = metadata.get("created_at")
            workspace_type = metadata.get("type", "temporary")
            
            if not created_str:
                continue
            
            # Check age
            created = datetime.fromisoformat(created_str)
            age_days = (datetime.utcnow() - created).days
            
            # Get max age for type
            type_enum = SessionType(workspace_type)
            max_age = max_age_days.get(type_enum)
            
            if max_age and age_days > max_age:
                workspace_path = Path(workspace["path"])
                
                if dry_run:
                    logger.info(
                        "Would clean up old workspace",
                        path=str(workspace_path),
                        age_days=age_days,
                        type=workspace_type
                    )
                else:
                    if await self.delete_workspace(workspace_path, force=True):
                        cleaned.append(workspace_path)
                        logger.info(
                            "Cleaned up old workspace",
                            path=str(workspace_path),
                            age_days=age_days,
                            type=workspace_type
                        )
        
        return cleaned
    
    async def _read_workspace_metadata(self, workspace_path: Path) -> Dict[str, Any]:
        """Read workspace metadata file."""
        metadata_file = workspace_path / ".mcp_workspace"
        
        if not metadata_file.exists():
            return {}
        
        try:
            async with aiofiles.open(metadata_file, 'r') as f:
                return json.loads(await f.read())
        except Exception as e:
            logger.error(
                "Failed to read workspace metadata",
                path=str(workspace_path),
                error=str(e)
            )
            return {}
    
    async def _is_valid_workspace(self, workspace_path: Path) -> bool:
        """Check if path is a valid workspace."""
        # Must be under root or temp directory
        try:
            workspace_path.relative_to(self.root_directory)
            return True
        except ValueError:
            pass
        
        try:
            workspace_path.relative_to(self.temp_directory)
            return True
        except ValueError:
            pass
        
        return False
    
    async def _archive_workspace(self, workspace_path: Path) -> bool:
        """Archive workspace instead of deleting."""
        try:
            # Create archive directory
            archive_dir = self.root_directory / ".archive"
            archive_dir.mkdir(exist_ok=True)
            
            # Generate archive name
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            archive_name = f"{workspace_path.name}_{timestamp}"
            archive_path = archive_dir / archive_name
            
            # Move workspace
            await aioshutil.move(str(workspace_path), str(archive_path))
            
            # Update metadata
            metadata_file = archive_path / ".mcp_workspace"
            if metadata_file.exists():
                metadata = await self._read_workspace_metadata(archive_path)
                metadata["archived_at"] = datetime.utcnow().isoformat()
                
                async with aiofiles.open(metadata_file, 'w') as f:
                    await f.write(json.dumps(metadata, indent=2))
            
            logger.info(
                "Archived workspace",
                original=str(workspace_path),
                archive=str(archive_path)
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to archive workspace",
                path=str(workspace_path),
                error=str(e)
            )
            return False
    
    def _generate_workspace_id(self, name: str) -> str:
        """Generate unique workspace ID."""
        # Sanitize name
        safe_name = PathUtils.sanitize_filename(name)
        
        # Add timestamp component
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # Add short hash for uniqueness
        hash_input = f"{safe_name}_{timestamp}_{os.getpid()}"
        short_hash = hashlib.md5(hash_input.encode()).hexdigest()[:6]
        
        return f"{safe_name}_{timestamp}_{short_hash}"
    
    async def create_workspace_snapshot(
        self,
        workspace_path: Path,
        snapshot_name: Optional[str] = None
    ) -> Optional[Path]:
        """
        Create a snapshot of workspace.
        
        Args:
            workspace_path: Workspace to snapshot
            snapshot_name: Optional snapshot name
            
        Returns:
            Path to snapshot or None on error
        """
        try:
            # Create snapshots directory
            snapshots_dir = workspace_path / ".snapshots"
            snapshots_dir.mkdir(exist_ok=True)
            
            # Generate snapshot name
            if not snapshot_name:
                snapshot_name = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            
            snapshot_path = snapshots_dir / snapshot_name
            
            # Copy workspace content (excluding snapshots)
            await aioshutil.copytree(
                str(workspace_path),
                str(snapshot_path),
                ignore=shutil.ignore_patterns(".snapshots", ".mcp_workspace", "*.tmp")
            )
            
            # Create snapshot metadata
            metadata = {
                "name": snapshot_name,
                "created_at": datetime.utcnow().isoformat(),
                "size_bytes": await self.get_workspace_size(snapshot_path)
            }
            
            metadata_file = snapshot_path / ".snapshot"
            async with aiofiles.open(metadata_file, 'w') as f:
                await f.write(json.dumps(metadata, indent=2))
            
            logger.info(
                "Created workspace snapshot",
                workspace=str(workspace_path),
                snapshot=str(snapshot_path)
            )
            
            return snapshot_path
            
        except Exception as e:
            logger.error(
                "Failed to create snapshot",
                workspace=str(workspace_path),
                error=str(e)
            )
            return None