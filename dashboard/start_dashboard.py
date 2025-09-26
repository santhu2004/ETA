#!/usr/bin/env python3
"""
Startup script for the Encrypted Traffic Analysis Dashboard
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    # Get the project root directory
    project_root = Path(__file__).parent.parent
    dashboard_dir = Path(__file__).parent
    
    print("🚀 Starting Encrypted Traffic Analysis Dashboard...")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not (project_root / "config.yaml").exists():
        print("❌ Error: config.yaml not found. Please run this from the project root.")
        print(f"   Expected config.yaml at: {project_root / 'config.yaml'}")
        sys.exit(1)
    
    # Check if virtual environment exists
    venv_python = project_root / "venv" / "bin" / "python"
    if not venv_python.exists():
        print("❌ Error: Virtual environment not found. Please run install.sh first.")
        print(f"   Expected venv at: {venv_python}")
        sys.exit(1)
    
    # Install dashboard dependencies
    print("📦 Installing dashboard dependencies...")
    try:
        subprocess.run([
            str(venv_python), "-m", "pip", "install", "-r", 
            str(dashboard_dir / "requirements.txt")
        ], check=True, cwd=str(project_root))
        print("✅ Dashboard dependencies installed")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        sys.exit(1)
    
    # Change to project root directory (Flask app needs to run from here)
    os.chdir(project_root)
    print(f"📁 Working directory: {os.getcwd()}")
    
    # Set up Flask app environment
    os.environ['FLASK_APP'] = 'dashboard/backend/app.py'
    os.environ['FLASK_ENV'] = 'development'
    
    print("\n🌐 Starting web server...")
    print("📍 Dashboard will be available at: http://localhost:5000")
    print("📍 Press Ctrl+C to stop the server")
    print("=" * 60)
    
    # Start the Flask app
    try:
        subprocess.run([
            str(venv_python), "dashboard/backend/app.py"
        ], cwd=str(project_root))
    except KeyboardInterrupt:
        print("\n\n⏹️ Dashboard stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting dashboard: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
