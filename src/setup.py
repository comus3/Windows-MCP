#!/usr/bin/env python3
"""
Setup script for MCP Windows Development Server.

This setup.py provides backward compatibility for legacy build systems
that don't support pyproject.toml. The canonical configuration is in
pyproject.toml - this file serves as a fallback.
"""

import sys
from pathlib import Path
from setuptools import setup, find_packages

# Ensure we're on Python 3.11+
if sys.version_info < (3, 11):
    sys.exit("mcp-windows-dev requires Python 3.11 or later")

# Ensure we're on Windows
if sys.platform != "win32":
    sys.exit("mcp-windows-dev requires Windows")

# Read the README file
here = Path(__file__).parent.resolve()
long_description = (here / "README.md").read_text(encoding="utf-8")

# Read requirements from requirements.txt
requirements_file = here / "requirements.txt"
requirements = []
dev_requirements = []
docs_requirements = []

if requirements_file.exists():
    with open(requirements_file, "r", encoding="utf-8") as f:
        current_section = "main"
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                # Check for section headers in comments
                if "Development Tools" in line:
                    current_section = "dev"
                elif "Documentation" in line:
                    current_section = "docs"
                continue
            
            # Skip development dependencies for main requirements
            if any(pkg in line for pkg in ["pytest", "black", "ruff", "mypy", "mkdocs"]):
                if current_section == "main":
                    continue
                elif "pytest" in line or "black" in line or "ruff" in line or "mypy" in line:
                    dev_requirements.append(line)
                elif "mkdocs" in line:
                    docs_requirements.append(line)
            else:
                if current_section == "main":
                    requirements.append(line)

# Core dependencies (extracted to avoid duplication)
CORE_REQUIREMENTS = [
    "mcp>=1.6.0",
    "pywin32>=306; sys_platform=='win32'",
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
]

DEV_REQUIREMENTS = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=4.1.0",
    "black>=24.0.0",
    "ruff>=0.2.0",
    "mypy>=1.8.0",
    "types-PyYAML>=6.0.12",
    "types-psutil>=5.9.5",
]

DOCS_REQUIREMENTS = [
    "mkdocs>=1.5.3",
    "mkdocs-material>=9.5.0",
    "mkdocstrings[python]>=0.24.0",
]

setup(
    name="mcp-windows-dev",
    version="1.0.0",
    author="MCP Windows Team",
    author_email="dev@mcp-windows.local",
    description="A secure Model Context Protocol (MCP) server for Windows development environments with granular access controls",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/comus3/Windows-MCP",
    project_urls={
        "Bug Reports": "https://github.com/comus3/Windows-MCP/issues",
        "Source": "https://github.com/comus3/Windows-MCP",
        "Documentation": "https://github.com/comus3/Windows-MCP#readme",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12", 
        "Programming Language :: Python :: 3.13",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
        "Environment :: Console",
        "Framework :: AsyncIO",
    ],
    keywords="mcp model-context-protocol windows development security workspace ai-assistant",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.11",
    install_requires=requirements or CORE_REQUIREMENTS,
    extras_require={
        "dev": dev_requirements or DEV_REQUIREMENTS,
        "docs": docs_requirements or DOCS_REQUIREMENTS,
        "test": [
            "pytest>=8.0.0",
            "pytest-asyncio>=0.23.0",
            "pytest-cov>=4.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mcp-windows=mcp_windows.main:main",
            "mcp-windows-dev=mcp_windows.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "mcp_windows": ["py.typed"],
    },
    zip_safe=False,
    platforms=["win32"],
    license="MIT",
    # Additional metadata for better package discovery
    maintainer="MCP Windows Team",
    maintainer_email="dev@mcp-windows.local",
)

if __name__ == "__main__":
    print("Setting up mcp-windows-dev...")
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")
    
    # Verify Windows platform
    if sys.platform != "win32":
        print("ERROR: This package requires Windows")
        sys.exit(1)
    
    # Verify Python version
    if sys.version_info < (3, 11):
        print(f"ERROR: Python 3.11+ required, got {sys.version_info.major}.{sys.version_info.minor}")
        sys.exit(1)
    
    print("Prerequisites check passed!")