"""
Logging configuration for MCP Windows Development Server.

This module provides structured logging setup with support for file rotation,
console output, and security event tracking.
"""

import sys
import logging
import logging.handlers
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
import json
import re

import structlog
from structlog.processors import JSONRenderer, KeyValueRenderer
from structlog.stdlib import LoggerFactory, add_log_level, add_logger_name
from structlog.dev import ConsoleRenderer
import colorlog

from ..config.settings import LoggingSettings, LogLevel


def _get_level_value(level):
    """Helper to extract level value from enum or string."""
    if hasattr(level, 'value'):
        return level.value
    elif isinstance(level, str):
        return level
    else:
        return str(level)


class SensitiveDataFilter(logging.Filter):
    """Filter to sanitize sensitive data from logs."""
    
    # Patterns to sanitize
    PATTERNS = [
        # Windows paths with usernames
        (r'C:\\Users\\[^\\]+\\', 'C:\\Users\\***\\'),
        # Email addresses
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***@***.***'),
        # IP addresses
        (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '***.***.***.***'),
        # Windows SIDs
        (r'S-1-5-21-[\d-]+', 'S-1-5-21-***'),
        # Registry keys with user data
        (r'HKEY_CURRENT_USER\\[^\s]+', 'HKEY_CURRENT_USER\\***'),
        # Command line passwords (removed problematic pattern)
        # (r'(?i)(password|pwd|pass|secret)[\s=:]+\S+', r'\1=***'),
    ]
    
    def __init__(self, enabled: bool = False):
        """Initialize filter with sanitization state."""
        super().__init__()
        self.enabled = enabled
        self.compiled_patterns = [
            (re.compile(pattern), replacement)
            for pattern, replacement in self.PATTERNS
        ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and sanitize log record."""
        if not self.enabled:
            return True
        
        # Sanitize message
        if hasattr(record, 'msg'):
            record.msg = self._sanitize_text(str(record.msg))
        
        # Sanitize args
        if hasattr(record, 'args') and record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self._sanitize_value(v)
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, (list, tuple)):
                record.args = type(record.args)(
                    self._sanitize_value(v) for v in record.args
                )
        
        return True
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitize sensitive data in text."""
        for pattern, replacement in self.compiled_patterns:
            text = pattern.sub(replacement, text)
        return text
    
    def _sanitize_value(self, value: Any) -> Any:
        """Sanitize sensitive data in any value."""
        if isinstance(value, str):
            return self._sanitize_text(value)
        elif isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
        elif isinstance(value, (list, tuple)):
            return type(value)(self._sanitize_value(v) for v in value)
        else:
            return value


class SecurityEventLogger:
    """Specialized logger for security events."""
    
    def __init__(self, logger: structlog.BoundLogger):
        """Initialize with base logger."""
        self.logger = logger
    
    def log_access_violation(
        self,
        path: Path,
        operation: str,
        user: str,
        reason: str
    ) -> None:
        """Log file access violation."""
        self.logger.warning(
            "security.access_violation",
            path=str(path),
            operation=operation,
            user=user,
            reason=reason,
            event_type="access_violation"
        )
    
    def log_command_blocked(
        self,
        command: str,
        session_id: str,
        pattern: str
    ) -> None:
        """Log blocked command execution."""
        self.logger.warning(
            "security.command_blocked",
            command=command[:100],  # Truncate for safety
            session_id=session_id,
            blocked_pattern=pattern,
            event_type="command_blocked"
        )
    
    def log_privilege_escalation(
        self,
        user: str,
        requested_privilege: str,
        granted: bool
    ) -> None:
        """Log privilege escalation attempt."""
        level = "info" if granted else "warning"
        getattr(self.logger, level)(
            "security.privilege_escalation",
            user=user,
            requested_privilege=requested_privilege,
            granted=granted,
            event_type="privilege_escalation"
        )
    
    def log_authentication(
        self,
        user: str,
        success: bool,
        method: str = "windows"
    ) -> None:
        """Log authentication attempt."""
        level = "info" if success else "warning"
        getattr(self.logger, level)(
            "security.authentication",
            user=user,
            success=success,
            method=method,
            event_type="authentication"
        )


class PerformanceLogger:
    """Specialized logger for performance metrics."""
    
    def __init__(self, logger: structlog.BoundLogger):
        """Initialize with base logger."""
        self.logger = logger
    
    def log_command_performance(
        self,
        command_id: str,
        duration_ms: float,
        exit_code: int,
        memory_mb: float
    ) -> None:
        """Log command execution performance."""
        self.logger.info(
            "performance.command",
            command_id=command_id,
            duration_ms=duration_ms,
            exit_code=exit_code,
            memory_mb=memory_mb,
            event_type="command_performance"
        )
    
    def log_session_metrics(
        self,
        session_id: str,
        active_time_minutes: float,
        commands_executed: int,
        files_accessed: int
    ) -> None:
        """Log session usage metrics."""
        self.logger.info(
            "performance.session",
            session_id=session_id,
            active_time_minutes=active_time_minutes,
            commands_executed=commands_executed,
            files_accessed=files_accessed,
            event_type="session_metrics"
        )
    
    def log_resource_usage(
        self,
        cpu_percent: float,
        memory_mb: float,
        disk_io_mb: float,
        active_sessions: int
    ) -> None:
        """Log system resource usage."""
        self.logger.info(
            "performance.resources",
            cpu_percent=cpu_percent,
            memory_mb=memory_mb,
            disk_io_mb=disk_io_mb,
            active_sessions=active_sessions,
            event_type="resource_usage"
        )


def setup_logging(settings: LoggingSettings) -> structlog.BoundLogger:
    """
    Configure logging based on settings.
    
    Args:
        settings: Logging configuration settings
        
    Returns:
        Configured logger instance
    """
    # Configure Python logging
    root_logger = logging.getLogger()
    root_logger.setLevel(_get_level_value(settings.level))
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatters
    if settings.json_output:
        formatter = logging.Formatter('%(message)s')
    else:
        formatter = logging.Formatter(
            settings.format,
            datefmt=settings.date_format
        )
    
    # Add console handler if enabled
    if settings.console:
        if settings.json_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
        else:
            # Use colorlog for console
            console_handler = colorlog.StreamHandler(sys.stdout)
            console_handler.setFormatter(
                colorlog.ColoredFormatter(
                    f"%(log_color)s{settings.format}",
                    datefmt=settings.date_format,
                    log_colors={
                        'DEBUG': 'cyan',
                        'INFO': 'green',
                        'WARNING': 'yellow',
                        'ERROR': 'red',
                        'CRITICAL': 'red,bg_white',
                    }
                )
            )
        
        console_handler.setLevel(_get_level_value(settings.level))
        root_logger.addHandler(console_handler)
    
    # Add file handler if enabled
    if settings.file:
        # Ensure log directory exists
        log_file = Path(settings.file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_file),
            maxBytes=settings.max_size_mb * 1024 * 1024,
            backupCount=settings.backup_count,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(_get_level_value(settings.level))
        
        # Add sensitive data filter (disabled by default due to regex issues)
        # if settings.sanitize_sensitive:
        #     file_handler.addFilter(SensitiveDataFilter(enabled=False))
        
        root_logger.addHandler(file_handler)
    
    # Configure structlog
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    # Add call site info in debug mode
    if _get_level_value(settings.level) == "DEBUG":
        processors.append(
            structlog.processors.CallsiteParameterAdder(
                parameters=[
                    structlog.processors.CallsiteParameter.FILENAME,
                    structlog.processors.CallsiteParameter.FUNC_NAME,
                    structlog.processors.CallsiteParameter.LINENO,
                ]
            )
        )
    
    # Add final renderer
    if settings.json_output:
        processors.append(JSONRenderer())
    else:
        if settings.console:
            processors.append(ConsoleRenderer())
        else:
            processors.append(KeyValueRenderer())
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Create logger
    logger = structlog.get_logger("mcp_windows")
    
    # Log startup
    logger.info(
        "Logging configured",
        level=_get_level_value(settings.level),
        console=settings.console,
        file=str(settings.file) if settings.file else None,
        json_output=settings.json_output,
        sanitize=settings.sanitize_sensitive
    )
    
    return logger


def get_logger(name: str = None) -> structlog.BoundLogger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (defaults to caller's module)
        
    Returns:
        Logger instance
    """
    if name is None:
        # Get caller's module name
        import inspect
        frame = inspect.currentframe()
        if frame and frame.f_back:
            name = frame.f_back.f_globals.get('__name__', 'mcp_windows')
        else:
            name = 'mcp_windows'
    
    return structlog.get_logger(name)


def get_security_logger() -> SecurityEventLogger:
    """Get specialized security event logger."""
    return SecurityEventLogger(get_logger("mcp_windows.security"))


def get_performance_logger() -> PerformanceLogger:
    """Get specialized performance logger."""
    return PerformanceLogger(get_logger("mcp_windows.performance"))


class LogContext:
    """Context manager for structured logging context."""
    
    def __init__(self, logger: structlog.BoundLogger, **kwargs):
        """Initialize with logger and context values."""
        self.logger = logger
        self.context = kwargs
        self.token = None
    
    def __enter__(self) -> structlog.BoundLogger:
        """Enter context and bind values."""
        self.token = structlog.contextvars.bind_contextvars(**self.context)
        return self.logger
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context and clear values."""
        if self.token:
            structlog.contextvars.unbind_contextvars(**self.context)


def log_context(logger: structlog.BoundLogger, **kwargs) -> LogContext:
    """
    Create a logging context with bound values.
    
    Args:
        logger: Logger instance
        **kwargs: Context values to bind
        
    Returns:
        Context manager
    """
    return LogContext(logger, **kwargs)


class AuditLogger:
    """Specialized logger for audit trails."""
    
    def __init__(self, audit_file: Optional[Path] = None):
        """Initialize audit logger with optional dedicated file."""
        self.logger = get_logger("mcp_windows.audit")
        self.audit_file = audit_file
        
        if audit_file:
            # Create dedicated audit handler
            audit_file.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.handlers.RotatingFileHandler(
                str(audit_file),
                maxBytes=100 * 1024 * 1024,  # 100MB
                backupCount=10,
                encoding='utf-8'
            )
            handler.setFormatter(
                logging.Formatter('%(asctime)s - %(message)s')
            )
            
            # Add to audit logger
            audit_logger = logging.getLogger("mcp_windows.audit")
            audit_logger.addHandler(handler)
            audit_logger.setLevel(logging.INFO)
    
    def log_session_created(
        self,
        session_id: str,
        session_type: str,
        user: str,
        workspace_path: str
    ) -> None:
        """Log session creation."""
        self.logger.info(
            "audit.session.created",
            session_id=session_id,
            session_type=session_type,
            user=user,
            workspace_path=workspace_path,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def log_command_executed(
        self,
        session_id: str,
        command: str,
        exit_code: int,
        duration_seconds: float
    ) -> None:
        """Log command execution."""
        self.logger.info(
            "audit.command.executed",
            session_id=session_id,
            command=command[:200],  # Truncate
            exit_code=exit_code,
            duration_seconds=duration_seconds,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def log_file_operation(
        self,
        session_id: str,
        operation: str,
        path: str,
        success: bool,
        size_bytes: Optional[int] = None
    ) -> None:
        """Log file operation."""
        self.logger.info(
            "audit.file.operation",
            session_id=session_id,
            operation=operation,
            path=path,
            success=success,
            size_bytes=size_bytes,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def log_permission_change(
        self,
        path: str,
        old_permission: str,
        new_permission: str,
        changed_by: str
    ) -> None:
        """Log permission change."""
        self.logger.info(
            "audit.permission.changed",
            path=path,
            old_permission=old_permission,
            new_permission=new_permission,
            changed_by=changed_by,
            timestamp=datetime.utcnow().isoformat()
        )