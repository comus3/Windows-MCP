"""
Main application entry point for MCP Windows Development Server.

This module provides the main server class and entry point for running
the MCP Windows development server.
"""

import asyncio
import signal
import sys
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP
import structlog

from .config.settings import MCPWindowsSettings, get_settings
from .core.session_manager import SessionManager
from .core.security_manager import SecurityManager
from .core.workspace_manager import WorkspaceManager
from .core.command_executor import CommandExecutor
from .registry.folder_registry import FolderRegistry
from .tools.session_tools import SessionTools
from .tools.command_tools import CommandTools
from .tools.file_tools import FileTools
from .utils.logging_config import setup_logging, get_logger

logger = get_logger(__name__)


class MCPWindowsServer:
    """
    Main MCP Windows Development Server.
    
    This class orchestrates all components and provides the MCP interface
    for AI assistants to manage local development workspaces.
    """
    
    def __init__(self, settings: Optional[MCPWindowsSettings] = None):
        """
        Initialize MCP Windows server.
        
        Args:
            settings: Configuration settings (uses defaults if None)
        """
        # Load settings
        self.settings = settings or get_settings()
        
        # Setup logging
        self.logger = setup_logging(self.settings.logging)
        
        # Initialize FastMCP
        self.mcp = FastMCP(
            name=self.settings.server_name,
            version=self.settings.server_version
        )
        
        # Core components (will be initialized in start())
        self.security_manager: Optional[SecurityManager] = None
        self.folder_registry: Optional[FolderRegistry] = None
        self.workspace_manager: Optional[WorkspaceManager] = None
        self.session_manager: Optional[SessionManager] = None
        self.command_executor: Optional[CommandExecutor] = None
        
        # Tool managers
        self.session_tools: Optional[SessionTools] = None
        self.command_tools: Optional[CommandTools] = None
        self.file_tools: Optional[FileTools] = None
        
        # Shutdown handling
        self._shutdown_event = asyncio.Event()
        self._setup_signal_handlers()
        
        logger.info(
            "MCP Windows Server initialized",
            version=self.settings.server_version,
            workspace_root=str(self.settings.workspace.root_directory)
        )
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(sig, frame):
            logger.info(f"Received signal {sig}, initiating shutdown...")
            self._shutdown_event.set()
        
        # Handle Ctrl+C and termination
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def start(self) -> None:
        """Start the MCP Windows server."""
        try:
            logger.info("Starting MCP Windows Server...")
            
            # Validate system requirements
            issues = self.settings.validate_system_requirements()
            if issues:
                logger.warning(
                    "System requirement issues detected",
                    issues=issues
                )
            
            # Initialize components in dependency order
            await self._initialize_components()
            
            # Register server information
            self._register_server_info()
            
            # Start MCP server
            logger.info(
                "MCP Windows Server started successfully",
                max_sessions=self.settings.max_sessions,
                security_mode=self.settings.security.mode.value
            )
            
            # Run server
            await self.mcp.run()
            
        except Exception as e:
            logger.error(
                "Failed to start MCP Windows Server",
                error=str(e),
                exc_info=True
            )
            raise
    
    async def _initialize_components(self) -> None:
        """Initialize all server components in proper order."""
        # 1. Security Manager (no dependencies)
        logger.info("Initializing Security Manager...")
        self.security_manager = SecurityManager(self.settings.security)
        await self.security_manager.initialize()
        
        # 2. Folder Registry (no dependencies)
        logger.info("Initializing Folder Registry...")
        self.folder_registry = FolderRegistry(self.settings)
        await self.folder_registry.initialize()
        
        # 3. Workspace Manager (depends on folder registry)
        logger.info("Initializing Workspace Manager...")
        self.workspace_manager = WorkspaceManager(
            self.settings.workspace,
            self.folder_registry
        )
        
        # 4. Session Manager (depends on workspace and security managers)
        logger.info("Initializing Session Manager...")
        self.session_manager = SessionManager(
            self.settings,
            self.workspace_manager,
            self.security_manager
        )
        await self.session_manager.initialize()
        
        # 5. Command Executor (depends on security and session managers)
        logger.info("Initializing Command Executor...")
        self.command_executor = CommandExecutor(
            self.settings,
            self.security_manager,
            self.session_manager
        )
        
        # 6. Initialize MCP tools
        logger.info("Initializing MCP tools...")
        self.session_tools = SessionTools(self.mcp, self.session_manager)
        self.command_tools = CommandTools(self.mcp, self.command_executor)
        self.file_tools = FileTools(
            self.mcp,
            self.session_manager,
            self.security_manager
        )
        
        logger.info("All components initialized successfully")
    
    def _register_server_info(self) -> None:
        """Register server information and capabilities."""
        
        @self.mcp.tool()
        async def get_server_info(ctx=None) -> dict:
            """
            Get information about the MCP Windows server.
            
            Returns server version, configuration, and current status.
            """
            return {
                "name": self.settings.server_name,
                "version": self.settings.server_version,
                "platform": sys.platform,
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "workspace_root": str(self.settings.workspace.root_directory),
                "security_mode": self.settings.security.mode.value,
                "features": {
                    "multi_shell": True,
                    "job_objects": self.settings.security.job_objects_enabled,
                    "folder_registry": True,
                    "session_persistence": True,
                    "command_isolation": True,
                    "file_operations": True
                },
                "limits": {
                    "max_sessions": self.settings.max_sessions,
                    "max_concurrent_commands": self.settings.max_concurrent_commands,
                    "command_timeout_seconds": self.settings.security.command_timeout_seconds,
                    "max_workspace_size_gb": self.settings.workspace.max_size_gb
                },
                "shells": {
                    "cmd": self.settings.shell.cmd_enabled,
                    "powershell": self.settings.shell.powershell_enabled,
                    "pwsh": self.settings.shell.pwsh_enabled,
                    "wsl": self.settings.shell.wsl_enabled
                }
            }
        
        @self.mcp.tool()
        async def get_server_health(ctx=None) -> dict:
            """
            Get server health and resource usage information.
            
            Returns current resource usage and component health status.
            """
            import psutil
            
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(str(self.settings.workspace.root_directory))
            
            # Get component health
            health = {
                "status": "healthy",
                "uptime_seconds": 0,  # Would need to track start time
                "system": {
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "memory_available_mb": memory.available // (1024 * 1024),
                    "disk_percent": disk.percent,
                    "disk_free_gb": disk.free // (1024 ** 3)
                },
                "components": {
                    "security_manager": "healthy" if self.security_manager else "not_initialized",
                    "session_manager": "healthy" if self.session_manager else "not_initialized",
                    "command_executor": "healthy" if self.command_executor else "not_initialized",
                    "workspace_manager": "healthy" if self.workspace_manager else "not_initialized",
                    "folder_registry": "healthy" if self.folder_registry else "not_initialized"
                }
            }
            
            # Get session metrics
            if self.session_manager:
                sessions = await self.session_manager.list_sessions()
                health["sessions"] = {
                    "total": len(sessions),
                    "active": sum(1 for s in sessions if s.state.value == "active")
                }
            
            # Get command metrics
            if self.command_executor:
                cmd_metrics = await self.command_executor.get_command_metrics()
                health["commands"] = cmd_metrics
            
            # Get security health
            if self.security_manager:
                sec_health = await self.security_manager.monitor_security_health()
                health["security"] = sec_health
            
            return health
        
        @self.mcp.tool()
        async def shutdown_server(confirm: bool = False, ctx=None) -> dict:
            """
            Gracefully shutdown the MCP Windows server.
            
            Args:
                confirm: Must be True to confirm shutdown
                
            Returns:
                Shutdown status
            """
            if not confirm:
                return {
                    "error": "Shutdown not confirmed. Set confirm=true to shutdown."
                }
            
            logger.info("Server shutdown requested via MCP")
            self._shutdown_event.set()
            
            return {
                "success": True,
                "message": "Server shutdown initiated"
            }
    
    async def shutdown(self) -> None:
        """Gracefully shutdown the server."""
        logger.info("Shutting down MCP Windows Server...")
        
        try:
            # Stop accepting new requests
            logger.info("Stopping new request processing...")
            
            # Clean up components in reverse order
            if self.command_executor:
                logger.info("Shutting down Command Executor...")
                await self.command_executor.cleanup()
            
            if self.session_manager:
                logger.info("Shutting down Session Manager...")
                await self.session_manager.shutdown()
            
            if self.workspace_manager:
                logger.info("Cleaning up Workspace Manager...")
                # Workspace manager doesn't need async cleanup
                pass
            
            if self.folder_registry:
                logger.info("Cleaning up Folder Registry...")
                await self.folder_registry.cleanup_expired_entries()
            
            if self.security_manager:
                logger.info("Shutting down Security Manager...")
                # Security manager cleanup handled by session manager
                pass
            
            logger.info("MCP Windows Server shutdown complete")
            
        except Exception as e:
            logger.error(
                "Error during shutdown",
                error=str(e),
                exc_info=True
            )
    
    async def run_with_shutdown(self) -> None:
        """Run server with graceful shutdown handling."""
        # Create tasks for server and shutdown monitor
        server_task = asyncio.create_task(self.start())
        shutdown_task = asyncio.create_task(self._shutdown_event.wait())
        
        # Wait for either server error or shutdown signal
        done, pending = await asyncio.wait(
            {server_task, shutdown_task},
            return_when=asyncio.FIRST_COMPLETED
        )
        
        # Cancel pending tasks
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        
        # Check for server errors
        for task in done:
            if task == server_task:
                try:
                    await task
                except Exception as e:
                    logger.error("Server task failed", error=str(e))
                    raise
        
        # Perform cleanup
        await self.shutdown()


def main():
    """Main entry point for MCP Windows Server."""
    # Parse command line arguments if needed
    import argparse
    
    parser = argparse.ArgumentParser(
        description="MCP Windows Development Server"
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode"
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        help="Override workspace root directory"
    )
    
    args = parser.parse_args()
    
    # Load settings
    settings = None
    if args.config and args.config.exists():
        settings = MCPWindowsSettings.from_yaml(args.config)
    else:
        settings = get_settings()
    
    # Apply command line overrides
    if args.debug:
        settings.debug_mode = True
        settings.logging.level = "DEBUG"
    
    if args.workspace_root:
        settings.workspace.root_directory = args.workspace_root
    
    # Create and run server
    server = MCPWindowsServer(settings)
    
    # Run with asyncio
    try:
        asyncio.run(server.run_with_shutdown())
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    except Exception as e:
        logger.error(
            "Server failed",
            error=str(e),
            exc_info=True
        )
        sys.exit(1)


if __name__ == "__main__":
    main()