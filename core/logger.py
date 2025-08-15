import os
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import logging


class EventLogger:
    """Logs security events and detections to multiple formats."""
    
    def __init__(self, logs_dir: str, log_level: str = "INFO"):
        self.logs_dir = logs_dir
        Path(logs_dir).mkdir(parents=True, exist_ok=True)
        
        # File paths
        self.jsonl_path = os.path.join(logs_dir, "detections.jsonl")
        self.sqlite_path = os.path.join(logs_dir, "detections.sqlite")
        self.summary_path = os.path.join(logs_dir, "summary.json")
        
        # Configure logging
        self._setup_logging(log_level)
        
        # Initialize databases
        self._init_sqlite()
        self._init_summary()

    def _setup_logging(self, log_level: str):
        """Setup Python logging configuration."""
        numeric_level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # File handler
        log_file = os.path.join(self.logs_dir, "system.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(numeric_level)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(numeric_level)
        
        # Configure root logger
        logging.basicConfig(
            level=numeric_level,
            handlers=[file_handler, console_handler],
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        self.logger = logging.getLogger(__name__)

    def _init_sqlite(self):
        """Initialize SQLite database with proper schema."""
        try:
            conn = sqlite3.connect(self.sqlite_path)
            cur = conn.cursor()
            
            # Create detections table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    indicator TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    confidence TEXT,
                    action TEXT NOT NULL,
                    packet_size INTEGER,
                    tls_sni TEXT,
                    tls_version TEXT,
                    cert_issuer TEXT,
                    cert_subject TEXT,
                    ja3_fingerprint TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better performance
            cur.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON detections(src_ip)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON detections(timestamp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_indicator ON detections(indicator)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_confidence ON detections(confidence)")
            
            conn.commit()
            conn.close()
            self.logger.info("SQLite database initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize SQLite database: {e}")

    def _init_summary(self):
        """Initialize summary statistics file."""
        if not os.path.exists(self.summary_path):
            summary = {
                "total_detections": 0,
                "indicators": {},
                "confidence_levels": {},
                "top_sources": {},
                "top_destinations": {},
                "last_updated": datetime.utcnow().isoformat() + "Z"
            }
            self._save_summary(summary)

    def _save_summary(self, summary: Dict):
        """Save summary statistics to file."""
        try:
            with open(self.summary_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save summary: {e}")

    def _update_summary(self, detection: Dict):
        """Update summary statistics with new detection."""
        try:
            with open(self.summary_path, "r", encoding="utf-8") as f:
                summary = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            summary = {
                "total_detections": 0,
                "indicators": {},
                "confidence_levels": {},
                "top_sources": {},
                "top_destinations": {},
                "last_updated": datetime.utcnow().isoformat() + "Z"
            }
        
        # Update counts
        summary["total_detections"] += 1
        
        # Update indicator counts
        indicator = detection.get("indicator", "unknown")
        summary["indicators"][indicator] = summary["indicators"].get(indicator, 0) + 1
        
        # Update confidence level counts
        confidence = detection.get("confidence", "unknown")
        summary["confidence_levels"][confidence] = summary["confidence_levels"].get(confidence, 0) + 1
        
        # Update top sources
        src_ip = detection.get("src_ip", "unknown")
        summary["top_sources"][src_ip] = summary["top_sources"].get(src_ip, 0) + 1
        
        # Update top destinations
        dst_ip = detection.get("dst_ip", "unknown")
        if dst_ip:
            summary["top_destinations"][dst_ip] = summary["top_destinations"].get(dst_ip, 0) + 1
        
        summary["last_updated"] = datetime.utcnow().isoformat() + "Z"
        
        self._save_summary(summary)

    def log(self, **kwargs):
        """Log a detection event with flexible parameters."""
        # Ensure required fields
        required_fields = ["src_ip", "indicator", "reason", "action"]
        for field in required_fields:
            if field not in kwargs:
                raise ValueError(f"Required field '{field}' missing from log call")
        
        # Create detection record
        detection = {
            "timestamp": kwargs.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            "src_ip": kwargs["src_ip"],
            "dst_ip": kwargs.get("dst_ip", ""),
            "src_port": kwargs.get("src_port"),
            "dst_port": kwargs.get("dst_port"),
            "protocol": kwargs.get("protocol", ""),
            "indicator": kwargs["indicator"],
            "reason": kwargs["reason"],
            "confidence": kwargs.get("confidence", "medium"),
            "action": kwargs["action"],
            "packet_size": kwargs.get("packet_size"),
            "tls_sni": kwargs.get("tls_sni"),
            "tls_version": kwargs.get("tls_version"),
            "cert_issuer": kwargs.get("cert_issuer"),
            "cert_subject": kwargs.get("cert_subject"),
            "ja3_fingerprint": kwargs.get("ja3_fingerprint")
        }
        
        # Log to JSONL
        self._log_jsonl(detection)
        
        # Log to SQLite
        self._log_sqlite(detection)
        
        # Update summary
        self._update_summary(detection)
        
        # Log to system logger
        self.logger.info(f"Detection: {detection['indicator']} from {detection['src_ip']} - {detection['reason']}")

    def _log_jsonl(self, detection: Dict):
        """Log detection to JSONL file."""
        try:
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(detection) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write to JSONL: {e}")

    def _log_sqlite(self, detection: Dict):
        """Log detection to SQLite database."""
        try:
            conn = sqlite3.connect(self.sqlite_path)
            cur = conn.cursor()
            
            cur.execute("""
                INSERT INTO detections (
                    timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                    indicator, reason, confidence, action, packet_size,
                    tls_sni, tls_version, cert_issuer, cert_subject, ja3_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                detection["timestamp"], detection["src_ip"], detection["dst_ip"],
                detection["src_port"], detection["dst_port"], detection["protocol"],
                detection["indicator"], detection["reason"], detection["confidence"],
                detection["action"], detection["packet_size"], detection["tls_sni"],
                detection["tls_version"], detection["cert_issuer"], detection["cert_subject"],
                detection["ja3_fingerprint"]
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to write to SQLite: {e}")

    def read_jsonl(self, limit: int = None) -> List[Dict]:
        """Read detections from JSONL file."""
        if not os.path.exists(self.jsonl_path):
            return []
        
        try:
            with open(self.jsonl_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if limit:
                    lines = lines[-limit:]
                
                detections = []
                for line in lines:
                    if line.strip():
                        try:
                            detections.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                
                return detections
        except Exception as e:
            self.logger.error(f"Failed to read JSONL: {e}")
            return []

    def read_sqlite(self, limit: int = None, filters: Dict = None) -> List[Dict]:
        """Read detections from SQLite database with optional filtering."""
        try:
            conn = sqlite3.connect(self.sqlite_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cur = conn.cursor()
            
            # Build query
            query = "SELECT * FROM detections"
            params = []
            
            if filters:
                conditions = []
                for key, value in filters.items():
                    if key in ["src_ip", "dst_ip", "indicator", "confidence"]:
                        conditions.append(f"{key} = ?")
                        params.append(value)
                    elif key == "since":
                        conditions.append("timestamp >= ?")
                        params.append(value)
                    elif key == "until":
                        conditions.append("timestamp <= ?")
                        params.append(value)
                
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY timestamp DESC"
            
            if limit:
                query += f" LIMIT {limit}"
            
            cur.execute(query, params)
            rows = cur.fetchall()
            
            # Convert to dictionaries
            detections = []
            for row in rows:
                detection = dict(row)
                detections.append(detection)
            
            conn.close()
            return detections
            
        except Exception as e:
            self.logger.error(f"Failed to read from SQLite: {e}")
            return []

    def get_statistics(self) -> Dict:
        """Get logging statistics."""
        try:
            with open(self.summary_path, "r", encoding="utf-8") as f:
                summary = json.load(f)
            return summary
        except Exception:
            return {
                "total_detections": 0,
                "indicators": {},
                "confidence_levels": {},
                "top_sources": {},
                "top_destinations": {},
                "last_updated": datetime.utcnow().isoformat() + "Z"
            }

    def export_detections(self, format: str = "json", filters: Dict = None) -> str:
        """Export detections in various formats."""
        detections = self.read_sqlite(filters=filters)
        
        if format.lower() == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            if detections:
                writer.writerow(detections[0].keys())
                for detection in detections:
                    writer.writerow(detection.values())
            
            return output.getvalue()
        
        elif format.lower() == "txt":
            lines = []
            for detection in detections:
                line = f"{detection['timestamp']} - {detection['src_ip']} -> {detection['indicator']}: {detection['reason']}"
                lines.append(line)
            return "\n".join(lines)
        
        else:  # JSON
            return json.dumps(detections, indent=2)

    def cleanup_old_logs(self, days: int = 30):
        """Clean up old log entries."""
        try:
            cutoff_date = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
            
            # Clean SQLite
            conn = sqlite3.connect(self.sqlite_path)
            cur = conn.cursor()
            cur.execute("DELETE FROM detections WHERE timestamp < ?", (cutoff_date,))
            deleted_count = cur.rowcount
            conn.commit()
            conn.close()
            
            # Clean JSONL (recreate file)
            if os.path.exists(self.jsonl_path):
                detections = self.read_sqlite(filters={"since": cutoff_date})
                with open(self.jsonl_path, "w", encoding="utf-8") as f:
                    for detection in detections:
                        f.write(json.dumps(detection) + "\n")
            
            self.logger.info(f"Cleaned up {deleted_count} old log entries")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old logs: {e}")

    def get_recent_detections(self, hours: int = 24) -> List[Dict]:
        """Get detections from the last N hours."""
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"
        return self.read_sqlite(filters={"since": since})

    def get_detections_by_ip(self, ip: str) -> List[Dict]:
        """Get all detections for a specific IP address."""
        return self.read_sqlite(filters={"src_ip": ip})

    def get_detections_by_indicator(self, indicator: str) -> List[Dict]:
        """Get all detections for a specific threat indicator."""
        return self.read_sqlite(filters={"indicator": indicator})
