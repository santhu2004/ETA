#!/usr/bin/env python3
"""
Flask backend for Encrypted Traffic Analysis Dashboard
Provides REST API endpoints that wrap around the existing CLI functionality
"""

import os
import sys
import json
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
import yaml
import shutil
import platform

# Helper: platform/admin detection
def _is_windows() -> bool:
    return os.name == 'nt'

def _is_posix() -> bool:
    return os.name == 'posix'

def _has_admin_privileges() -> bool:
    try:
        if _is_windows():
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        if _is_posix():
            return os.geteuid() == 0
    except Exception:
        return False
    return False

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Change to project root directory
os.chdir(project_root)

from core.analysis import Analyzer
from core.mitigation import Mitigator
from core.logger import EventLogger

# Configure Flask app with correct template and static directories
dashboard_dir = Path(__file__).parent.parent
app = Flask(__name__, 
           template_folder=str(dashboard_dir / 'frontend' / 'templates'),
           static_folder=str(dashboard_dir / 'frontend' / 'static'))
CORS(app)

# Global variables for capture state
capture_process = None
capture_status = {"running": False, "packets": 0, "flagged": 0, "start_time": None}


def load_config():
    """Load configuration from config.yaml"""
    config_path = project_root / "config.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_python_cmd():
    """Get the correct Python command with virtual environment"""
    venv_python = project_root / "venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return "python"


def run_cli_command(cmd_args, use_sudo=False):
    """Run CLI command and return output"""
    python_cmd = get_python_cmd()
    
    if use_sudo:
        full_cmd = ["sudo", "-E", "env", "PATH=" + os.environ.get("PATH", ""), python_cmd, "-m", "cli.main"] + cmd_args
    else:
        full_cmd = [python_cmd, "-m", "cli.main"] + cmd_args
    
    try:
        # Run from project root directory
        result = subprocess.run(
            full_cmd, 
            capture_output=True, 
            text=True, 
            timeout=30,
            cwd=str(project_root)
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.route('/')
def index():
    """Serve the landing page"""
    return render_template('landing.html')


@app.route('/dashboard')
def dashboard_page():
    """Serve the main dashboard page (respects ?mode=live|simulation)"""
    # The JS will read mode from URL if needed; we just render the page
    return render_template('index.html')


@app.route('/api/status')
def get_status():
    """Get current system status"""
    cfg = load_config()
    
    # Get basic stats
    try:
        logger = EventLogger(cfg["paths"]["logs_dir"])
        mitigator = Mitigator(
            state_dir=cfg["paths"]["state_dir"],
            mode=cfg.get("mode", "simulate"),
            block_duration_seconds=cfg.get("block_duration_seconds", 300)
        )
        
        stats = {
            "capture": capture_status,
            "system": {
                "total_detections": logger.get_statistics()["total_detections"],
                "total_blocked": mitigator.get_statistics()["total_blocked"],
                "last_updated": logger.get_statistics()["last_updated"]
            }
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """Start live traffic capture"""
    global capture_process, capture_status
    
    if capture_status["running"]:
        return jsonify({"error": "Capture is already running"}), 400
    
    try:
        # Ensure dashboard outputs directory exists for logs
        outputs_dir = dashboard_dir / 'outputs'
        outputs_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = outputs_dir / 'live_capture.log'
        stderr_path = outputs_dir / 'live_capture.err'

        # Build command according to platform/privileges
        python_cmd = get_python_cmd()
        base_cmd = [python_cmd, "-m", "cli.main", "capture"]
        
        stdin_spec = subprocess.DEVNULL
        pre_write_password = None
        
        if _is_windows():
            # On Windows, do not attempt sudo; require Admin privileges
            cmd = base_cmd
            if not _has_admin_privileges():
                return jsonify({
                    "error": (
                        "Live capture requires Administrator privileges on Windows. "
                        "Please start the dashboard from an elevated PowerShell (Run as Administrator). "
                        "Also ensure Npcap is installed with WinPcap API compatibility."
                    )
                }), 500
        else:
            # POSIX (Linux/macOS): ALWAYS elevate for live capture unless already root
            if _has_admin_privileges():
                cmd = base_cmd
            else:
                sudo_cmd = shutil.which('sudo')
                if not sudo_cmd:
                    return jsonify({
                        "error": (
                            "Live capture requires elevated privileges and 'sudo' was not found. "
                            "Run the dashboard as root or grant CAP_NET_RAW to Python."
                        )
                    }), 500
                # Prefer sudo -S with password from env if provided; otherwise, try non-interactive -n
                sudo_password = os.environ.get('ETA_SUDO_PASSWORD')
                if sudo_password:
                    cmd = [sudo_cmd, "-S", "-E", "-p", "", "env", "PATH=" + os.environ.get("PATH", "")] + base_cmd
                    stdin_spec = subprocess.PIPE
                    pre_write_password = sudo_password + "\n"
                else:
                    cmd = [sudo_cmd, "-n", "-E", "env", "PATH=" + os.environ.get("PATH", "")] + base_cmd
        
        # Open log files and start process without piping to avoid deadlocks
        stdout_f = open(stdout_path, 'a')
        stderr_f = open(stderr_path, 'a')
        
        capture_process = subprocess.Popen(
            cmd,
            stdout=stdout_f,
            stderr=stderr_f,
            stdin=stdin_spec,
            text=True,
            cwd=str(project_root)
        )
        
        # If we need to send sudo password, write it immediately then close stdin
        if pre_write_password is not None and capture_process.stdin:
            try:
                capture_process.stdin.write(pre_write_password)
                capture_process.stdin.flush()
            finally:
                try:
                    capture_process.stdin.close()
                except Exception:
                    pass

        # Brief health check: if process exited immediately (e.g., sudo needs password or missing deps)
        time.sleep(0.5)
        if capture_process.poll() is not None and capture_process.returncode is not None and capture_process.returncode != 0:
            try:
                err_msg = ''
                if stderr_path.exists():
                    with open(stderr_path, 'r', encoding='utf-8', errors='ignore') as ef:
                        lines = ef.readlines()
                        err_msg = ''.join(lines[-50:])
            except Exception:
                err_msg = ''

            guidance = []
            if _is_windows():
                guidance.append("Run the dashboard from an elevated PowerShell (Run as Administrator).")
                guidance.append("Install Npcap with WinPcap API compatibility: https://npcap.com/")
            else:
                if not _has_admin_privileges():
                    if os.environ.get('ETA_SUDO_PASSWORD') is None:
                        guidance.append("Set ETA_SUDO_PASSWORD environment variable for the dashboard process to allow non-interactive sudo.")
                        guidance.append("Example: ETA_SUDO_PASSWORD=yourpassword venv/bin/python dashboard/backend/app.py")
                        guidance.append("Alternatively, configure passwordless sudo for this command, or run the dashboard as root.")
                guidance.append("Grant capabilities to Python to allow raw sockets without sudo (optional):")
                guidance.append("  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f venv/bin/python)")
                guidance.append("For PyShark, ensure 'dumpcap' has required capabilities: sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)")

            capture_status = {"running": False, "packets": 0, "flagged": 0, "start_time": None}
            return jsonify({
                "error": (
                    f"Live capture failed to start (code {capture_process.returncode}). "
                    f"{err_msg}\n" + "\n".join(guidance)
                )
            }), 500
        
        capture_status = {
            "running": True,
            "packets": 0,
            "flagged": 0,
            "start_time": datetime.now().isoformat()
        }
        
        return jsonify({"success": True, "message": "Capture started"})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to start capture: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """Stop live traffic capture"""
    global capture_process, capture_status
    
    if not capture_status["running"]:
        return jsonify({"error": "No capture is running"}), 400
    
    try:
        if capture_process:
            capture_process.terminate()
            try:
                capture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture_process.kill()
                capture_process.wait()
        
        capture_status["running"] = False
        return jsonify({"success": True, "message": "Capture stopped"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/capture/replay', methods=['POST'])
def start_replay():
    """Start replay mode with simulated data"""
    try:
        # First generate some test data if it doesn't exist
        cfg = load_config()
        data_file = Path(cfg["paths"]["data_dir"]) / "simulated_flows.jsonl"
        
        if not data_file.exists():
            result = run_cli_command(["simulate", "--count", "100", "--malicious-ratio", "0.3"])
            if not result["success"]:
                return jsonify({"error": "Failed to generate test data: " + result.get("error", "Unknown error")}), 500
        
        # Start replay
        result = run_cli_command(["capture", "--replay"])
        return jsonify({
            "success": result["success"],
            "output": result["stdout"],
            "error": result.get("stderr", "")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/logs')
def get_logs():
    """Get recent detection logs"""
    try:
        cfg = load_config()
        logger = EventLogger(cfg["paths"]["logs_dir"])
        logs = logger.read_jsonl()
        
        # Return last 100 logs, newest first
        return jsonify(logs[-100:][::-1])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    try:
        cfg = load_config()
        
        analyzer = Analyzer(
            rules_paths={
                "bad_ips": cfg["paths"]["bad_ips"],
                "ja3_blacklist": cfg["paths"]["ja3_blacklist"],
                "suspicious_domains": cfg["paths"].get("suspicious_domains", ""),
                "cert_blacklist": cfg["paths"].get("cert_blacklist", "")
            },
            thresholds=cfg["thresholds"]
        )
        
        mitigator = Mitigator(
            state_dir=cfg["paths"]["state_dir"],
            mode=cfg.get("mode", "simulate"),
            block_duration_seconds=cfg.get("block_duration_seconds", 300)
        )
        
        logger = EventLogger(cfg["paths"]["logs_dir"])
        
        stats = {
            "analysis": analyzer.get_statistics(),
            "mitigation": mitigator.get_statistics(),
            "logging": logger.get_statistics()
        }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/blocks')
def get_blocks():
    """Get list of blocked IPs"""
    try:
        cfg = load_config()
        mitigator = Mitigator(
            state_dir=cfg["paths"]["state_dir"],
            mode=cfg.get("mode", "simulate"),
            block_duration_seconds=cfg.get("block_duration_seconds", 300)
        )
        
        blocks = mitigator.list_blocks()
        return jsonify(blocks)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/unblock', methods=['POST'])
def unblock_ip():
    """Unblock an IP address"""
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    try:
        result = run_cli_command(["unblock", "--ip", ip])
        return jsonify({
            "success": result["success"],
            "message": result["stdout"] if result["success"] else result["stderr"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    """Clear all logs"""
    try:
        cfg = load_config()
        logger = EventLogger(cfg["paths"]["logs_dir"])
        logger.clear_logs()
        return jsonify({"success": True, "message": "All logs cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/export', methods=['POST'])
def export_data():
    """Export data in various formats"""
    data = request.get_json()
    export_type = data.get('type', 'logs')
    export_format = data.get('format', 'json')
    hours = data.get('hours')
    
    try:
        cmd = ["export", "--type", export_type, "--format", export_format]
        if hours:
            cmd.extend(["--hours", str(hours)])
        
        result = run_cli_command(cmd)
        return jsonify({
            "success": result["success"],
            "message": result["stdout"] if result["success"] else result["stderr"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # Ensure output directories exist
    cfg = load_config()
    for key in ("outputs_dir", "data_dir", "logs_dir", "state_dir", "exports_dir"):
        if key in cfg["paths"]:
            os.makedirs(cfg["paths"][key], exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)