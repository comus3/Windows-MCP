"""
Configuration settings for MCP Windows Development Server.

This module provides centralized configuration management using Pydantic settings
with support for environment variables, YAML files, and Windows Registry.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from enum import Enum

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import structlog
import yaml

logger = structlog.get_logger(__name__)


class LogLevel(str, Enum):
    """Logging levels."""
    
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SecurityMode(str, Enum):
    """Security operation modes."""
    
    PERMISSIVE = "permissive"  # Log violations but allow
    STRICT = "strict"          # Block violations
    PARANOID = "paranoid"      # Block violations with enhanced checks


class WorkspaceSettings(BaseSettings):
    """Workspace configuration settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="MCP_WORKSPACE_",
        case_sensitive=False
    )
    
    # Paths
    root_directory: Path = Field(
        default=Path("C:/mcp_workspaces"),
        description="Root directory for all workspaces"
    )
    temp_directory: Optional[Path] = Field(
        default=None,
        description="Temporary directory for ephemeral files"
    )
    
    # Size limits
    max_size_gb: int = Field(
        default=10,
        ge=1,
        le=1000,
        description="Maximum workspace size in GB"
    )
    max_file_size_mb: int = Field(
        default=100,
        ge=1,
        le=10240,
        description="Maximum individual file size in MB"
    )
    
    # Permissions
    default_permissions: str = Field(
        default="755",
        pattern=r"^[0-7]{3,4}$",
        description="Default Unix-style permissions"
    )
    
    # Cleanup policy
    cleanup_enabled: bool = Field(
        default=True,
        description="Enable automatic cleanup"
    )
    cleanup_interval_hours: int = Field(
        default=1,
        ge=1,
        le=24,
        description="Cleanup check interval in hours"
    )
    temporary_retention_hours: int = Field(
        default=24,
        ge=1,
        le=168,
        description="Retention for temporary sessions"
    )
    experiment_retention_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description="Retention for experiment sessions"
    )
    
    # Structure
    create_default_structure: bool = Field(
        default=True,
        description="Create default directory structure"
    )
    default_directories: List[str] = Field(
        default_factory=lambda: [
            "src",
            "tests", 
            "docs",
            "data",
            ".vscode"
        ],
        description="Default directories to create"
    )
    
    @field_validator("root_directory", "temp_directory")
    @classmethod
    def validate_directory(cls, v: Optional[Path]) -> Optional[Path]:
        """Ensure directories are absolute."""
        if v is not None:
            v = Path(v).resolve()
            if not v.is_absolute():
                raise ValueError("Directory must be absolute path")
        return v
    
    @model_validator(mode="after")
    def set_temp_directory(self) -> "WorkspaceSettings":
        """Set temp directory if not specified."""
        if self.temp_directory is None:
            self.temp_directory = self.root_directory / ".temp"
        return self


class SecuritySettings(BaseSettings):
    """Security configuration settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="MCP_SECURITY_",
        case_sensitive=False
    )
    
    # Mode
    mode: SecurityMode = Field(
        default=SecurityMode.STRICT,
        description="Security enforcement mode"
    )
    
    # Job Objects
    job_objects_enabled: bool = Field(
        default=True,
        description="Use Windows Job Objects for process isolation"
    )
    max_processes: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Maximum processes per job"
    )
    max_memory_mb: int = Field(
        default=2048,
        ge=128,
        le=32768,
        description="Maximum memory per job in MB"
    )
    max_cpu_percent: Optional[int] = Field(
        default=None,
        ge=1,
        le=100,
        description="Maximum CPU usage percentage"
    )
    
    # Command execution
    command_timeout_seconds: int = Field(
        default=300,
        ge=10,
        le=86400,
        description="Default command timeout"
    )
    allowed_shells: Set[str] = Field(
        default_factory=lambda: {"cmd", "powershell", "pwsh"},
        description="Allowed shell types"
    )
    blocked_commands: List[str] = Field(
        default_factory=lambda: [
            "format",
            "diskpart",
            "net user",
            "net localgroup",
            "shutdown",
            "bcdedit"
        ],
        description="Blocked command patterns"
    )
    allowed_extensions: Set[str] = Field(
        default_factory=lambda: {
            ".exe", ".bat", ".cmd", ".ps1", 
            ".py", ".js", ".sh"
        },
        description="Allowed executable extensions"
    )
    
    # Network
    network_access: bool = Field(
        default=False,
        description="Allow network access"
    )
    allowed_domains: List[str] = Field(
        default_factory=list,
        description="Allowed network domains"
    )
    firewall_integration: bool = Field(
        default=True,
        description="Integrate with Windows Firewall"
    )
    
    # ACL management
    acl_enforcement: bool = Field(
        default=True,
        description="Enforce Windows ACLs"
    )
    inherit_parent_acls: bool = Field(
        default=False,
        description="Inherit ACLs from parent"
    )
    
    # Registry
    registry_virtualization: bool = Field(
        default=True,
        description="Enable registry virtualization"
    )
    registry_write_allowed: bool = Field(
        default=False,
        description="Allow registry writes"
    )
    
    @field_validator("allowed_shells", "allowed_extensions")
    @classmethod
    def normalize_set(cls, v: Set[str]) -> Set[str]:
        """Normalize string sets to lowercase."""
        return {item.lower() for item in v}
    
    @field_validator("blocked_commands")
    @classmethod
    def normalize_list(cls, v: List[str]) -> List[str]:
        """Normalize command list to lowercase."""
        return [cmd.lower() for cmd in v]


class ShellSettings(BaseSettings):
    """Shell-specific configuration settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="MCP_SHELL_",
        case_sensitive=False
    )
    
    # CMD settings
    cmd_enabled: bool = Field(default=True)
    cmd_path: Optional[Path] = Field(
        default=None,
        description="Override CMD path"
    )
    cmd_encoding: str = Field(
        default="cp1252",
        description="CMD default encoding"
    )
    cmd_extensions: bool = Field(
        default=True,
        description="Enable CMD extensions"
    )
    
    # PowerShell settings
    powershell_enabled: bool = Field(default=True)
    powershell_path: Optional[Path] = Field(
        default=None,
        description="Override PowerShell path"
    )
    powershell_execution_policy: str = Field(
        default="RemoteSigned",
        description="PowerShell execution policy"
    )
    
    # PowerShell Core settings
    pwsh_enabled: bool = Field(default=True)
    pwsh_path: Optional[Path] = Field(
        default=None,
        description="Override PowerShell Core path"
    )
    pwsh_execution_policy: str = Field(
        default="RemoteSigned",
        description="PowerShell Core execution policy"
    )
    
    # WSL settings
    wsl_enabled: bool = Field(default=False)
    wsl_default_distribution: Optional[str] = Field(
        default=None,
        description="Default WSL distribution"
    )
    wsl_path: Optional[Path] = Field(
        default=None,
        description="Override WSL path"
    )
    
    # Shell behavior
    shell_startup_timeout: int = Field(
        default=10,
        ge=1,
        le=60,
        description="Shell startup timeout in seconds"
    )
    preserve_environment: bool = Field(
        default=False,
        description="Preserve parent environment"
    )
    interactive_mode: bool = Field(
        default=False,
        description="Enable interactive shell mode"
    )


class LoggingSettings(BaseSettings):
    """Logging configuration settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="MCP_LOG_",
        case_sensitive=False
    )
    
    # Basic settings
    level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging level"
    )
    file: Optional[Path] = Field(
        default=Path("mcp_windows.log"),
        description="Log file path"
    )
    console: bool = Field(
        default=True,
        description="Enable console logging"
    )
    
    # File rotation
    max_size_mb: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum log file size in MB"
    )
    backup_count: int = Field(
        default=5,
        ge=0,
        le=100,
        description="Number of backup files"
    )
    
    # Format
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log message format"
    )
    date_format: str = Field(
        default="%Y-%m-%d %H:%M:%S",
        description="Date format"
    )
    
    # Structured logging
    structured: bool = Field(
        default=True,
        description="Enable structured logging"
    )
    json_output: bool = Field(
        default=False,
        description="Output logs as JSON"
    )
    
    # Security
    log_commands: bool = Field(
        default=True,
        description="Log executed commands"
    )
    log_file_access: bool = Field(
        default=True,
        description="Log file access"
    )
    sanitize_sensitive: bool = Field(
        default=True,
        description="Sanitize sensitive data"
    )
    
    @field_validator("file")
    @classmethod
    def validate_file(cls, v: Optional[Path]) -> Optional[Path]:
        """Ensure log file path is valid."""
        if v is not None:
            v = Path(v)
            if not v.parent.exists():
                v.parent.mkdir(parents=True, exist_ok=True)
        return v


class MCPWindowsSettings(BaseSettings):
    """Main configuration settings for MCP Windows server."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="MCP_",
        case_sensitive=False,
        extra="allow"
    )
    
    # Sub-configurations
    workspace: WorkspaceSettings = Field(default_factory=WorkspaceSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    shell: ShellSettings = Field(default_factory=ShellSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    
    # Server settings
    server_name: str = Field(
        default="MCP Windows Development Server",
        description="Server display name"
    )
    server_version: str = Field(
        default="1.0.0",
        description="Server version"
    )
    
    # Session settings
    max_sessions: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum concurrent sessions"
    )
    session_idle_timeout_minutes: Optional[int] = Field(
        default=60,
        ge=1,
        le=1440,
        description="Session idle timeout"
    )
    
    # Registry settings
    registry_key: str = Field(
        default=r"SOFTWARE\MCPWindows",
        description="Windows Registry key"
    )
    user_settings_key: str = Field(
        default=r"SOFTWARE\MCPWindows\UserSettings",
        description="User settings Registry key"
    )
    
    # Performance
    max_concurrent_commands: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Maximum concurrent commands"
    )
    cache_enabled: bool = Field(
        default=True,
        description="Enable caching"
    )
    cache_size_mb: int = Field(
        default=100,
        ge=10,
        le=1000,
        description="Cache size in MB"
    )
    
    # Development
    debug_mode: bool = Field(
        default=False,
        description="Enable debug mode"
    )
    profiling_enabled: bool = Field(
        default=False,
        description="Enable performance profiling"
    )
    
    @classmethod
    def from_yaml(cls, path: Path) -> "MCPWindowsSettings":
        """Load settings from YAML file."""
        if not path.exists():
            logger.warning(f"Config file not found: {path}")
            return cls()
        
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}
            
            # Parse nested settings
            return cls(**data)
        except Exception as e:
            logger.error(f"Failed to load config from {path}: {e}")
            return cls()
    
    @classmethod
    def from_registry(cls) -> "MCPWindowsSettings":
        """Load settings from Windows Registry."""
        import winreg
        
        settings_dict = {}
        
        try:
            # Open registry key
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\MCPWindows",
                0,
                winreg.KEY_READ
            ) as key:
                # Read values
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        settings_dict[name] = value
                        i += 1
                    except WindowsError:
                        break
        except Exception as e:
            logger.debug(f"No registry settings found: {e}")
        
        return cls(**settings_dict)
    
    def to_registry(self) -> None:
        """Save settings to Windows Registry."""
        import winreg
        
        try:
            # Create or open registry key
            with winreg.CreateKey(
                winreg.HKEY_LOCAL_MACHINE,
                self.registry_key
            ) as key:
                # Write basic settings
                data = self.model_dump()
                for name, value in data.items():
                    if isinstance(value, (str, int, bool)):
                        winreg.SetValueEx(
                            key,
                            name,
                            0,
                            winreg.REG_SZ if isinstance(value, str) else winreg.REG_DWORD,
                            str(value) if isinstance(value, bool) else value
                        )
        except Exception as e:
            logger.error(f"Failed to save settings to registry: {e}")
    
    def validate_system_requirements(self) -> List[str]:
        """Validate system requirements and return any issues."""
        issues = []
        
        # Check Python version
        import sys
        if sys.version_info < (3, 11):
            issues.append(f"Python 3.11+ required, found {sys.version}")
        
        # Check Windows version
        if sys.platform != "win32":
            issues.append(f"Windows required, found {sys.platform}")
        
        # Check workspace directory
        if not self.workspace.root_directory.exists():
            try:
                self.workspace.root_directory.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                issues.append(f"Cannot create workspace directory: {e}")
        
        # Check available disk space
        try:
            import shutil
            stat = shutil.disk_usage(self.workspace.root_directory)
            free_gb = stat.free / (1024 ** 3)
            if free_gb < self.workspace.max_size_gb:
                issues.append(
                    f"Insufficient disk space: {free_gb:.1f}GB free, "
                    f"{self.workspace.max_size_gb}GB required"
                )
        except Exception as e:
            issues.append(f"Cannot check disk space: {e}")
        
        # Check shell availability
        shells_found = []
        if self.shell.cmd_enabled:
            cmd_path = self.shell.cmd_path or Path("C:/Windows/System32/cmd.exe")
            if cmd_path.exists():
                shells_found.append("cmd")
        
        if self.shell.powershell_enabled:
            ps_path = self.shell.powershell_path or Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
            if ps_path.exists():
                shells_found.append("powershell")
        
        if not shells_found:
            issues.append("No supported shells found")
        
        return issues
    
    def get_effective_settings(self) -> Dict[str, Any]:
        """Get effective settings as a flat dictionary."""
        return {
            "workspace_root": str(self.workspace.root_directory),
            "security_mode": self.security.mode.value,
            "max_sessions": self.max_sessions,
            "max_processes": self.security.max_processes,
            "max_memory_mb": self.security.max_memory_mb,
            "command_timeout": self.security.command_timeout_seconds,
            "allowed_shells": list(self.security.allowed_shells),
            "network_access": self.security.network_access,
            "log_level": self.logging.level.value,
            "debug_mode": self.debug_mode,
        }


# Global settings instance
_settings: Optional[MCPWindowsSettings] = None


def get_settings() -> MCPWindowsSettings:
    """Get global settings instance."""
    global _settings
    
    if _settings is None:
        # Try loading from various sources
        config_paths = [
            Path("config.yaml"),
            Path("mcp_windows.yaml"),
            Path.home() / ".mcp_windows" / "config.yaml",
            Path(os.getenv("PROGRAMDATA", "C:/ProgramData")) / "MCPWindows" / "config.yaml",
        ]
        
        for path in config_paths:
            if path.exists():
                logger.info(f"Loading configuration from {path}")
                _settings = MCPWindowsSettings.from_yaml(path)
                break
        else:
            # Try registry
            _settings = MCPWindowsSettings.from_registry()
            
            # Fall back to environment/defaults
            if not _settings:
                _settings = MCPWindowsSettings()
        
        # Validate system requirements
        issues = _settings.validate_system_requirements()
        if issues:
            logger.warning(
                "System requirement issues detected",
                issues=issues
            )
    
    return _settings


def reload_settings() -> None:
    """Reload settings from sources."""
    global _settings
    _settings = None
    get_settings()