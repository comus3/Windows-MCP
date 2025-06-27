"""
MCP Windows Development Server

A secure Model Context Protocol (MCP) server designed for Windows environments
that enables AI assistants to manage local development workspaces with granular
access controls.

This package provides:
- Isolated workspaces with Windows Job Objects
- Multi-shell support (CMD, PowerShell, WSL)
- Folder authorization registry with ACL management
- Session lifecycle management
- Security-first design with process isolation

Example:
    >>> from mcp_windows import create_server
    >>> server = create_server()
    >>> await server.start()
"""

__version__ = "1.0.0"
__author__ = "MCP Windows Team"
__email__ = "dev@mcp-windows.local"
__license__ = "MIT"

import sys
from typing import TYPE_CHECKING

# Ensure we're running on Windows
if sys.platform != "win32":
    raise ImportError(
        "mcp-windows-dev requires Windows. "
        "Detected platform: {}".format(sys.platform)
    )

# Ensure Python version
if sys.version_info < (3, 11):
    raise ImportError(
        "mcp-windows-dev requires Python 3.11 or later. "
        "Current version: {}.{}".format(sys.version_info.major, sys.version_info.minor)
    )

# Type checking imports
if TYPE_CHECKING:
    from .core.session_manager import SessionManager
    from .core.security_manager import SecurityManager
    from .core.workspace_manager import WorkspaceManager
    from .core.command_executor import CommandExecutor
    from .models.session import Session, SessionType, SessionMetadata
    from .models.command_result import CommandResult
    from .models.file_info import FileInfo
    from .models.registry_entry import RegistryEntry, PermissionLevel

# Public API exports
__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    
    # Factory functions
    "create_server",
    "create_session_manager",
    "create_security_manager",
    "create_workspace_manager",
    "create_command_executor",
    
    # Core managers
    "SessionManager",
    "SecurityManager", 
    "WorkspaceManager",
    "CommandExecutor",
    
    # Models
    "Session",
    "SessionType",
    "SessionMetadata",
    "CommandResult",
    "FileInfo",
    "RegistryEntry",
    "PermissionLevel",
    
    # Exceptions
    "MCPWindowsException",
    "SecurityViolationError",
    "WorkspaceError",
    "SessionError",
    "CommandExecutionError",
    "RegistryError",
]

# Lazy imports for performance
_SERVER = None
_SESSION_MANAGER = None
_SECURITY_MANAGER = None
_WORKSPACE_MANAGER = None
_COMMAND_EXECUTOR = None


def create_server(**kwargs):
    """
    Create and configure an MCP Windows server instance.
    
    Args:
        **kwargs: Configuration options for the server
        
    Returns:
        MCPWindowsServer: Configured server instance ready to start
        
    Example:
        >>> server = create_server(
        ...     workspace_root="C:\\mcp_workspaces",
        ...     max_sessions=10,
        ...     security_enabled=True
        ... )
        >>> await server.start()
    """
    global _SERVER
    if _SERVER is None:
        from .main import MCPWindowsServer
        _SERVER = MCPWindowsServer(**kwargs)
    return _SERVER


def create_session_manager(**kwargs) -> "SessionManager":
    """Create a session manager instance."""
    global _SESSION_MANAGER
    if _SESSION_MANAGER is None:
        from .core.session_manager import SessionManager
        _SESSION_MANAGER = SessionManager(**kwargs)
    return _SESSION_MANAGER


def create_security_manager(**kwargs) -> "SecurityManager":
    """Create a security manager instance."""
    global _SECURITY_MANAGER
    if _SECURITY_MANAGER is None:
        from .core.security_manager import SecurityManager
        _SECURITY_MANAGER = SecurityManager(**kwargs)
    return _SECURITY_MANAGER


def create_workspace_manager(**kwargs) -> "WorkspaceManager":
    """Create a workspace manager instance."""
    global _WORKSPACE_MANAGER
    if _WORKSPACE_MANAGER is None:
        from .core.workspace_manager import WorkspaceManager
        _WORKSPACE_MANAGER = WorkspaceManager(**kwargs)
    return _WORKSPACE_MANAGER


def create_command_executor(**kwargs) -> "CommandExecutor":
    """Create a command executor instance."""
    global _COMMAND_EXECUTOR
    if _COMMAND_EXECUTOR is None:
        from .core.command_executor import CommandExecutor
        _COMMAND_EXECUTOR = CommandExecutor(**kwargs)
    return _COMMAND_EXECUTOR


# Exception classes
class MCPWindowsException(Exception):
    """Base exception for all MCP Windows operations."""
    
    def __init__(self, message: str, code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}
    
    def __str__(self):
        if self.code:
            return f"[{self.code}] {self.message}"
        return self.message


class SecurityViolationError(MCPWindowsException):
    """Raised when security policies are violated."""
    
    def __init__(self, message: str, path: str = None, operation: str = None):
        super().__init__(
            message,
            code="SECURITY_VIOLATION",
            details={"path": path, "operation": operation}
        )


class WorkspaceError(MCPWindowsException):
    """Raised for workspace management issues."""
    
    def __init__(self, message: str, workspace_id: str = None):
        super().__init__(
            message,
            code="WORKSPACE_ERROR",
            details={"workspace_id": workspace_id}
        )


class SessionError(MCPWindowsException):
    """Raised for session management issues."""
    
    def __init__(self, message: str, session_id: str = None):
        super().__init__(
            message,
            code="SESSION_ERROR",
            details={"session_id": session_id}
        )


class CommandExecutionError(MCPWindowsException):
    """Raised when command execution fails."""
    
    def __init__(self, message: str, command: str = None, exit_code: int = None):
        super().__init__(
            message,
            code="COMMAND_ERROR",
            details={"command": command, "exit_code": exit_code}
        )


class RegistryError(MCPWindowsException):
    """Raised for registry operation failures."""
    
    def __init__(self, message: str, key: str = None):
        super().__init__(
            message,
            code="REGISTRY_ERROR",
            details={"key": key}
        )


# Package initialization logging
def _initialize_logging():
    """Initialize package-level logging configuration."""
    import logging
    import structlog
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.CallsiteParameterAdder(
                parameters=[
                    structlog.processors.CallsiteParameter.FILENAME,
                    structlog.processors.CallsiteParameter.FUNC_NAME,
                    structlog.processors.CallsiteParameter.LINENO,
                ]
            ),
            structlog.processors.dict_tracebacks,
            structlog.dev.ConsoleRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Set up basic logging
    logging.basicConfig(
        format="%(message)s",
        level=logging.INFO,
    )


# Initialize logging on import
_initialize_logging()

# Log package initialization
import structlog
logger = structlog.get_logger(__name__)
logger.info(
    "MCP Windows Development Server initialized",
    version=__version__,
    platform=sys.platform,
    python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
)