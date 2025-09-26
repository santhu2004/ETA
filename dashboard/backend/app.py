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
    """Serve the main dashboard page"""
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
        # Start capture in background
        python_cmd = get_python_cmd()
        cmd = ["sudo", "-E", "env", "PATH=" + os.environ.get("PATH", ""), python_cmd, "-m", "cli.main", "capture"]
        
        capture_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(project_root)
        )
        
        capture_status = {
            "running": True,
            "packets": 0,
            "flagged": 0,
            "start_time": datetime.now().isoformat()
        }
        
        return jsonify({"success": True, "message": "Capture started"})
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
        result = run_cli_command(["clear-logs"])
        return jsonify({
            "success": result["success"],
            "message": result["stdout"] if result["success"] else result["stderr"]
        })
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
