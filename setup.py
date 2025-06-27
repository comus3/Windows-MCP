"""
Setup script for MCP Windows Development Server.

This script handles installation, dependency management, and platform checks
for the MCP Windows development server.
"""

import os
import sys
import platform
from pathlib import Path
from setuptools import setup, find_packages
from setuptools.command.install import install


def check_platform():
    """Check if running on Windows."""
    if sys.platform != "win32":
        print("ERROR: mcp-windows-dev requires Windows")
        print(f"Current platform: {sys.platform}")
        sys.exit(1)


def check_python_version():
    """Check Python version."""
    if sys.version_info < (3, 11):
        print("ERROR: mcp-windows-dev requires Python 3.11 or later")
        print(f"Current version: {sys.version}")
        sys.exit(1)


def check_admin_privileges():
    """Check if running with admin privileges (optional warning)."""
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("WARNING: Some features may require administrator privileges")
            print("Consider running installation as administrator for full functionality")
    except Exception:
        pass


def get_version():
    """Get version from package."""
    version_file = Path(__file__).parent / "src" / "mcp_windows" / "__init__.py"
    if version_file.exists():
        with open(version_file, "r") as f:
            for line in f:
                if line.startswith("__version__"):
                    return line.split("=")[1].strip().strip('"').strip("'")
    return "1.0.0"


def read_requirements():
    """Read requirements from requirements.txt."""
    req_file = Path(__file__).parent / "requirements.txt"
    if req_file.exists():
        with open(req_file, "r") as f:
            # Skip comments and empty lines
            reqs = []
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Skip optional/dev dependencies
                    if any(marker in line for marker in ["pytest", "black", "ruff", "mypy", "mkdocs"]):
                        continue
                    reqs.append(line)
            return reqs
    return []


class CustomInstallCommand(install):
    """Custom installation command with post-install steps."""
    
    def run(self):
        """Run installation."""
        # Run standard installation
        install.run(self)
        
        # Post-install steps
        self.post_install()
    
    def post_install(self):
        """Perform post-installation setup."""
        print("\n" + "="*60)
        print("MCP Windows Development Server Installation Complete!")
        print("="*60)
        
        # Create default directories
        try:
            from mcp_windows.config.settings import get_settings
            settings = get_settings()
            
            # Create workspace root
            workspace_root = settings.workspace.root_directory
            workspace_root.mkdir(parents=True, exist_ok=True)
            print(f"✓ Created workspace directory: {workspace_root}")
            
            # Create session store
            session_store = workspace_root / ".sessions"
            session_store.mkdir(exist_ok=True)
            print(f"✓ Created session store: {session_store}")
            
            # Create audit directory
            audit_dir = workspace_root / ".audit"
            audit_dir.mkdir(exist_ok=True)
            print(f"✓ Created audit directory: {audit_dir}")
            
        except Exception as e:
            print(f"⚠ Could not create default directories: {e}")
        
        print("\nNext Steps:")
        print("1. Configure authorized folders:")
        print("   mcp-windows-configure --authorize-folder C:\\YourProjects")
        print("\n2. Start the server:")
        print("   mcp-windows")
        print("\n3. Configure your AI client to connect to the MCP server")
        print("\nFor more information, see the documentation.")
        print("="*60 + "\n")


# Platform and version checks
check_platform()
check_python_version()
check_admin_privileges()

# Package metadata
setup(
    name="mcp-windows-dev",
    version=get_version(),
    author="MCP Windows Team",
    author_email="dev@mcp-windows.local",
    description="A secure Model Context Protocol (MCP) server for Windows environments",
    long_description=open("README.md").read() if Path("README.md").exists() else "",
    long_description_content_type="text/markdown",
    url="https://github.com/mcp-windows/mcp-windows-dev",
    project_urls={
        "Bug Tracker": "https://github.com/mcp-windows/mcp-windows-dev/issues",
        "Documentation": "https://mcp-windows.readthedocs.io",
        "Source Code": "https://github.com/mcp-windows/mcp-windows-dev",
    },
    
    # Package configuration
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    package_data={
        "mcp_windows": [
            "config/*.yaml",
            "config/*.yml",
            "py.typed",
        ],
    },
    
    # Dependencies
    python_requires=">=3.11",
    install_requires=read_requirements() or [
        "mcp>=1.6.0",
        "pywin32>=306",
        "psutil>=5.9.0",
        "aiofiles>=23.0.0",
        "aioshutil>=1.3",
        "asyncio-throttle>=1.0.2",
        "pydantic>=2.5.0",
        "pydantic-settings>=2.1.0",
        "cryptography>=42.0.0",
        "pyyaml>=6.0.1",
        "python-dotenv>=1.0.0",
        "structlog>=24.1.0",
        "colorlog>=6.8.0",
        "pathspec>=0.12.1",
        "watchdog>=4.0.0",
    ],
    
    # Optional dependencies
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-asyncio>=0.23.0",
            "pytest-cov>=4.1.0",
            "black>=24.0.0",
            "ruff>=0.2.0",
            "mypy>=1.8.0",
            "types-PyYAML>=6.0.12",
            "types-psutil>=5.9.5",
        ],
        "docs": [
            "mkdocs>=1.5.3",
            "mkdocs-material>=9.5.0",
            "mkdocstrings[python]>=0.24.0",
        ],
    },
    
    # Entry points
    entry_points={
        "console_scripts": [
            "mcp-windows=mcp_windows.main:main",
            "mcp-windows-configure=mcp_windows.tools.configure:main",
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Win32 (MS Windows)",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Operating System :: Microsoft :: Windows :: Windows 11",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
        "Typing :: Typed",
    ],
    
    # Custom commands
    cmdclass={
        "install": CustomInstallCommand,
    },
    
    # Additional metadata
    keywords=[
        "mcp",
        "model-context-protocol",
        "windows",
        "development",
        "security",
        "sandbox",
        "ai",
        "assistant",
        "workspace",
    ],
    
    # License
    license="MIT",
    
    # Zip safety
    zip_safe=False,
)


# Windows-specific post-install registry setup (optional)
def setup_windows_registry():
    """Setup Windows registry entries (requires admin)."""
    try:
        import winreg
        
        # Create registry key for MCP Windows
        key_path = r"SOFTWARE\MCPWindows"
        
        try:
            # Try HKEY_LOCAL_MACHINE first (requires admin)
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                winreg.SetValueEx(key, "InstallPath", 0, winreg.REG_SZ, str(Path(__file__).parent))
                winreg.SetValueEx(key, "Version", 0, winreg.REG_SZ, get_version())
                print(f"✓ Created system registry key: HKLM\\{key_path}")
        except PermissionError:
            # Fall back to HKEY_CURRENT_USER
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "InstallPath", 0, winreg.REG_SZ, str(Path(__file__).parent))
                winreg.SetValueEx(key, "Version", 0, winreg.REG_SZ, get_version())
                print(f"✓ Created user registry key: HKCU\\{key_path}")
                
    except Exception as e:
        print(f"⚠ Could not setup registry: {e}")


# Run registry setup if installing
if "install" in sys.argv:
    try:
        setup_windows_registry()
    except Exception:
        pass