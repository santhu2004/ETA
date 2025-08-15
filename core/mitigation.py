import os
import json
import platform
import subprocess
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Mitigator:
    """Handles IP blocking and unblocking for detected threats."""
    
    def __init__(self, state_dir: str, mode: str = "simulate", block_duration_seconds: int = 300):
        Path(state_dir).mkdir(parents=True, exist_ok=True)
        self.state_dir = state_dir
        self.mode = mode
        self.block_duration_seconds = block_duration_seconds
        self.block_file = os.path.join(state_dir, "blocked_ips.json")
        self.system = platform.system().lower()
        self._ensure_block_file()
        
        # Validate system compatibility
        if mode == "enforce" and self.system not in ["windows", "linux"]:
            logger.warning(f"Enforcement mode not fully supported on {self.system}. Using simulation mode.")
            self.mode = "simulate"

    def _ensure_block_file(self):
        """Ensure the blocked IPs file exists with proper structure."""
        if not os.path.exists(self.block_file):
            with open(self.block_file, "w", encoding="utf-8") as f:
                json.dump({"blocks": [], "last_updated": datetime.utcnow().isoformat() + "Z"}, f)

    def _load_blocks(self) -> Dict:
        """Load blocked IPs from state file."""
        try:
            with open(self.block_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            # Reset file if corrupted
            logger.warning("Block file corrupted, resetting...")
            return {"blocks": [], "last_updated": datetime.utcnow().isoformat() + "Z"}

    def _save_blocks(self, data: Dict):
        """Save blocked IPs to state file."""
        data["last_updated"] = datetime.utcnow().isoformat() + "Z"
        with open(self.block_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _cleanup_expired_blocks(self):
        """Remove expired blocks from the system."""
        data = self._load_blocks()
        now = datetime.utcnow()
        expired_blocks = []
        
        for block in data["blocks"]:
            try:
                expires_at = datetime.fromisoformat(block["expires_at"].replace("Z", ""))
                if expires_at < now:
                    expired_blocks.append(block["ip"])
                    if self.mode == "enforce":
                        self._unblock_ip_system(block["ip"])
            except Exception as e:
                logger.error(f"Error parsing expiry date for {block['ip']}: {e}")
        
        # Remove expired blocks from state
        if expired_blocks:
            data["blocks"] = [b for b in data["blocks"] if b["ip"] not in expired_blocks]
            self._save_blocks(data)
            logger.info(f"Cleaned up {len(expired_blocks)} expired blocks")
        
        return expired_blocks

    def _block_ip_windows(self, ip: str) -> bool:
        """Block IP using Windows netsh advfirewall."""
        try:
            rule_name = f"Block_EncryptedTraffic_{ip}"
            
            # Check if rule already exists
            check_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
            result = subprocess.run(check_cmd, capture_output=True, text=True, shell=True)
            
            if "No rules match the specified criteria" not in result.stdout:
                # Rule exists, update it
                delete_cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(delete_cmd, capture_output=True, shell=True)
            
            # Create new blocking rule
            block_cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
                "description=Blocked by Encrypted Traffic Analysis"
            ]
            
            result = subprocess.run(block_cmd, capture_output=True, shell=True)
            if result.returncode == 0:
                logger.info(f"Successfully blocked IP {ip} on Windows")
                return True
            else:
                logger.error(f"Failed to block IP {ip} on Windows: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip} on Windows: {e}")
            return False

    def _block_ip_linux(self, ip: str) -> bool:
        """Block IP using Linux iptables."""
        try:
            # Check if rule already exists
            check_cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(check_cmd, capture_output=True)
            
            if result.returncode == 0:
                logger.info(f"IP {ip} already blocked on Linux")
                return True
            
            # Add blocking rule
            block_cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(block_cmd, capture_output=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully blocked IP {ip} on Linux")
                return True
            else:
                logger.error(f"Failed to block IP {ip} on Linux: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip} on Linux: {e}")
            return False

    def _unblock_ip_windows(self, ip: str) -> bool:
        """Unblock IP using Windows netsh advfirewall."""
        try:
            rule_name = f"Block_EncryptedTraffic_{ip}"
            delete_cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            
            result = subprocess.run(delete_cmd, capture_output=True, shell=True)
            if result.returncode == 0:
                logger.info(f"Successfully unblocked IP {ip} on Windows")
                return True
            else:
                logger.error(f"Failed to unblock IP {ip} on Windows: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error unblocking IP {ip} on Windows: {e}")
            return False

    def _unblock_ip_linux(self, ip: str) -> bool:
        """Unblock IP using Linux iptables."""
        try:
            # Remove blocking rule
            unblock_cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(unblock_cmd, capture_output=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully unblocked IP {ip} on Linux")
                return True
            else:
                logger.error(f"Failed to unblock IP {ip} on Linux: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error unblocking IP {ip} on Linux: {e}")
            return False

    def _block_ip_system(self, ip: str) -> bool:
        """Block IP using system-specific commands."""
        if self.system == "windows":
            return self._block_ip_windows(ip)
        elif self.system == "linux":
            return self._block_ip_linux(ip)
        else:
            logger.warning(f"IP blocking not implemented for {self.system}")
            return False

    def _unblock_ip_system(self, ip: str) -> bool:
        """Unblock IP using system-specific commands."""
        if self.system == "windows":
            return self._unblock_ip_windows(ip)
        elif self.system == "linux":
            return self._unblock_ip_linux(ip)
        else:
            logger.warning(f"IP unblocking not implemented for {self.system}")
            return False

    def block_ip(self, ip: str, reason: str, confidence: str = "medium") -> bool:
        """Block an IP address for the configured duration."""
        # Clean up expired blocks first
        self._cleanup_expired_blocks()
        
        data = self._load_blocks()
        now = datetime.utcnow()
        expiry = now + timedelta(seconds=self.block_duration_seconds)
        
        # Check if IP is already blocked
        existing_block = next((b for b in data["blocks"] if b["ip"] == ip), None)
        
        if existing_block:
            # Update existing block
            existing_block["expires_at"] = expiry.isoformat() + "Z"
            existing_block["reason"] = reason
            existing_block["confidence"] = confidence
            existing_block["last_updated"] = now.isoformat() + "Z"
            existing_block["block_count"] = existing_block.get("block_count", 0) + 1
        else:
            # Add new block
            data["blocks"].append({
                "ip": ip,
                "reason": reason,
                "confidence": confidence,
                "created_at": now.isoformat() + "Z",
                "last_updated": now.isoformat() + "Z",
                "expires_at": expiry.isoformat() + "Z",
                "block_count": 1
            })
        
        # Save to state file
        self._save_blocks(data)
        
        # Apply system blocking if in enforce mode
        if self.mode == "enforce":
            success = self._block_ip_system(ip)
            if not success:
                logger.error(f"Failed to block IP {ip} at system level")
                return False
        
        logger.info(f"IP {ip} blocked until {expiry.isoformat()}. Reason: {reason}")
        return True

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        data = self._load_blocks()
        
        # Check if IP is actually blocked
        if not any(b["ip"] == ip for b in data["blocks"]):
            logger.warning(f"IP {ip} is not currently blocked")
            return False
        
        # Remove from state
        data["blocks"] = [b for b in data["blocks"] if b["ip"] != ip]
        self._save_blocks(data)
        
        # Remove from system if in enforce mode
        if self.mode == "enforce":
            success = self._unblock_ip_system(ip)
            if not success:
                logger.error(f"Failed to unblock IP {ip} at system level")
                return False
        
        logger.info(f"IP {ip} unblocked successfully")
        return True

    def list_blocks(self) -> List[Dict]:
        """List all currently blocked IPs."""
        # Clean up expired blocks first
        self._cleanup_expired_blocks()
        
        data = self._load_blocks()
        return data["blocks"]

    def get_block_status(self, ip: str) -> Optional[Dict]:
        """Get blocking status for a specific IP."""
        blocks = self.list_blocks()
        return next((b for b in blocks if b["ip"] == ip), None)

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        return self.get_block_status(ip) is not None

    def get_statistics(self) -> Dict:
        """Get mitigation statistics."""
        blocks = self.list_blocks()
        now = datetime.utcnow()
        
        # Calculate statistics
        total_blocks = len(blocks)
        high_confidence = len([b for b in blocks if b.get("confidence") == "high"])
        medium_confidence = len([b for b in blocks if b.get("confidence") == "medium"])
        low_confidence = len([b for b in blocks if b.get("confidence") == "low"])
        
        # Calculate average block duration
        durations = []
        for block in blocks:
            try:
                created = datetime.fromisoformat(block["created_at"].replace("Z", ""))
                expires = datetime.fromisoformat(block["expires_at"].replace("Z", ""))
                duration = (expires - created).total_seconds()
                durations.append(duration)
            except:
                pass
        
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        return {
            "total_blocked": total_blocks,
            "high_confidence": high_confidence,
            "medium_confidence": medium_confidence,
            "low_confidence": low_confidence,
            "average_block_duration_seconds": avg_duration,
            "system": self.system,
            "mode": self.mode,
            "last_updated": now.isoformat() + "Z"
        }

    def export_blocks(self, format: str = "json") -> str:
        """Export blocked IPs in various formats."""
        blocks = self.list_blocks()
        
        if format.lower() == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["IP", "Reason", "Confidence", "Created", "Expires", "Block Count"])
            
            for block in blocks:
                writer.writerow([
                    block["ip"],
                    block["reason"],
                    block.get("confidence", ""),
                    block["created_at"],
                    block["expires_at"],
                    block.get("block_count", 1)
                ])
            
            return output.getvalue()
        
        elif format.lower() == "txt":
            lines = []
            for block in blocks:
                lines.append(f"{block['ip']} - {block['reason']} (expires: {block['expires_at']})")
            return "\n".join(lines)
        
        else:  # JSON
            return json.dumps(blocks, indent=2)
