#!/usr/bin/env python3
"""
DeepDomain v2.0 Installation Script
Automatically installs dependencies and sets up the tool
"""

import os
import sys
import subprocess
import platform

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    DeepDomain v2.0 Installer                ║
║              Advanced Subdomain Enumeration Tool            ║
╚══════════════════════════════════════════════════════════════╝
    """)

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 6):
        print("❌ Python 3.6+ is required. Current version:", sys.version)
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} detected")
    return True

def install_requirements():
    """Install required packages"""
    print("\n📦 Installing required packages...")
    
    requirements = [
        "requests>=2.25.0",
        "urllib3>=1.26.0", 
        "tqdm>=4.60.0"
    ]
    
    for package in requirements:
        try:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✅ {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {package}: {e}")
            return False
    
    return True

def create_launcher_script():
    """Create a launcher script for easier execution"""
    system = platform.system().lower()
    
    if system == "windows":
        # Create batch file for Windows
        launcher_content = """@echo off
py "%~dp0deepdomain.py" %*
"""
        with open("deepdomain.bat", "w") as f:
            f.write(launcher_content)
        print("✅ Created deepdomain.bat launcher for Windows")
        
    else:
        # Create shell script for Linux/Mac
        launcher_content = """#!/bin/bash
python3 "$(dirname "$0")/deepdomain.py" "$@"
"""
        with open("deepdomain", "w") as f:
            f.write(launcher_content)
        os.chmod("deepdomain", 0o755)
        print("✅ Created deepdomain launcher script for Unix/Linux")

def run_test():
    """Run a quick test to verify installation"""
    print("\n🧪 Running installation test...")
    try:
        result = subprocess.run([sys.executable, "deepdomain.py", "--version"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ Installation test passed!")
            return True
        else:
            print(f"❌ Installation test failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Installation test failed: {e}")
        return False

def main():
    print_banner()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        print("\n❌ Installation failed. Please install dependencies manually:")
        print("pip install requests urllib3 tqdm")
        sys.exit(1)
    
    # Create launcher script
    create_launcher_script()
    
    # Run test
    if not run_test():
        print("\n⚠️  Installation completed but test failed.")
        print("You can still try running the tool manually.")
    
    print(f"""
🎉 Installation completed successfully!

📖 Quick Start:
   python deepdomain.py example.com --all
   
📚 Get help:
   python deepdomain.py -h
   
📁 Check the README.md file for detailed documentation.

Happy subdomain hunting! 🔍
    """)

if __name__ == "__main__":
    main()
