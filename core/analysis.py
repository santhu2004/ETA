import os
import json
import re
from datetime import datetime
from statistics import pstdev
from typing import Dict, List, Optional, Tuple
from dateutil import parser


def load_bad_ips(path: str) -> set:
    """Load list of known bad IP addresses."""
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())


def load_ja3_blacklist(path: str) -> set:
    """Load list of known malicious JA3 fingerprints."""
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return set(data.get("bad_fingerprints", []))


def load_suspicious_domains(path: str) -> set:
    """Load list of suspicious domain patterns."""
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())


def load_certificate_blacklist(path: str) -> Dict:
    """Load certificate issuer/subject blacklist."""
    if not os.path.exists(path):
        return {"issuers": set(), "subjects": set()}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {
        "issuers": set(data.get("bad_issuers", [])),
        "subjects": set(data.get("bad_subjects", []))
    }


class Analyzer:
    """Analyzes encrypted traffic metadata for security threats."""
    
    def __init__(self, rules_paths: Dict, thresholds: Dict):
        self.bad_ips = load_bad_ips(rules_paths.get("bad_ips", ""))
        self.ja3_blacklist = load_ja3_blacklist(rules_paths.get("ja3_blacklist", ""))
        self.suspicious_domains = load_suspicious_domains(rules_paths.get("suspicious_domains", ""))
        self.cert_blacklist = load_certificate_blacklist(rules_paths.get("cert_blacklist", ""))
        self.thresholds = thresholds
        
        # Compile regex patterns for efficiency
        self.suspicious_patterns = [
            re.compile(r'\.(xyz|top|tk|ml|ga|cf|gq|pw)$', re.IGNORECASE),  # Suspicious TLDs
            re.compile(r'(update|sync|backup|admin|api)\.', re.IGNORECASE),  # Suspicious subdomains
            re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'),  # IP-like domains
        ]

    def _check_bad_ip(self, packet_data: Dict) -> Optional[Tuple[str, str]]:
        """Check if source IP is in the bad IP list."""
        src_ip = packet_data.get("src_ip", "")
        if src_ip in self.bad_ips:
            return ("bad_ip", f"Source IP {src_ip} is on static blocklist")
        return None

    def _check_ja3_fingerprint(self, packet_data: Dict) -> Optional[Tuple[str, str]]:
        """Check if JA3 fingerprint is blacklisted."""
        ja3 = packet_data.get("ja3_fingerprint")
        if ja3 and ja3 in self.ja3_blacklist:
            return ("ja3_blacklist", f"JA3 fingerprint {ja3} is blacklisted")
        return None

    def _check_certificate_issues(self, packet_data: Dict) -> Optional[Tuple[str, str]]:
        """Check for suspicious certificate characteristics."""
        # Check issuer blacklist
        issuer = packet_data.get("cert_issuer", "")
        if issuer and issuer.lower() in self.cert_blacklist.get("issuers", set()):
            return ("cert_blacklisted_issuer", f"Certificate issuer '{issuer}' is blacklisted")
        
        # Check subject blacklist
        subject = packet_data.get("cert_subject", "")
        if subject and subject.lower() in self.cert_blacklist.get("subjects", set()):
            return ("cert_blacklisted_subject", f"Certificate subject '{subject}' is blacklisted")
        
        # Check for self-signed certificates
        if issuer and ("self-signed" in issuer.lower() or "self signed" in issuer.lower()):
            return ("cert_self_signed", "Certificate issuer indicates self-signed certificate")
        
        # Check certificate expiration
        try:
            valid_to = packet_data.get("cert_valid_to")
            if valid_to:
                if isinstance(valid_to, str):
                    dt = parser.parse(valid_to)
                else:
                    dt = valid_to
                if dt < datetime.utcnow():
                    return ("cert_expired", f"Certificate expired at {valid_to}")
        except Exception:
            # If parsing fails, flag as suspicious
            return ("cert_parse_error", "Could not parse certificate validity date")
        
        return None

    def _check_suspicious_domain(self, packet_data: Dict) -> Optional[Tuple[str, str]]:
        """Check for suspicious domain patterns in SNI."""
        sni = packet_data.get("tls_sni", "")
        if not sni:
            return None
            
        # Check against suspicious domain list
        if sni in self.suspicious_domains:
            return ("suspicious_domain", f"Domain '{sni}' is in suspicious domain list")
        
        # Check against regex patterns
        for pattern in self.suspicious_patterns:
            if pattern.search(sni):
                return ("suspicious_domain_pattern", f"Domain '{sni}' matches suspicious pattern")
        
        return None

    def _check_port_anomalies(self, packet_data: Dict) -> Optional[Tuple[str, str]]:
        """Check for unusual port usage patterns."""
        dst_port = packet_data.get("dst_port", 0)
        protocol = packet_data.get("protocol", "")
        
        # Check for non-standard HTTPS ports
        if protocol == "TCP" and dst_port not in [80, 443, 8080, 8443]:
            if dst_port < 1024:  # Well-known ports
                return ("unusual_port", f"Unusual destination port {dst_port} for HTTPS traffic")
        
        # Check for common malware ports
        malware_ports = {4444, 8080, 8443, 9000, 9001, 9002}
        if dst_port in malware_ports:
            return ("malware_port", f"Destination port {dst_port} commonly used by malware")
        
        return None

    def _check_tls_anomalies(self, packet_data: Dict) -> Optional[Tuple[str, str]]:
        """Check for suspicious TLS characteristics."""
        tls_version = packet_data.get("tls_version", "")
        cipher_suite = packet_data.get("tls_cipher_suite", "")
        
        # Check for old/weak TLS versions
        if tls_version in ["1.0", "1.1"]:
            return ("weak_tls_version", f"Using weak TLS version {tls_version}")
        
        # Check for null cipher suites (if available)
        if cipher_suite and "NULL" in cipher_suite.upper():
            return ("null_cipher", "TLS cipher suite contains NULL encryption")
        
        return None

    def _check_behavioral_anomalies(self, packet_data: Dict) -> Optional[Tuple[str, str]]:
        """Check for behavioral anomalies in packet characteristics."""
        packet_size = packet_data.get("packet_size", 0)
        ttl = packet_data.get("ttl")
        
        # Check for unusually small packets (potential scanning)
        if packet_size > 0 and packet_size < 60:
            return ("small_packet", f"Unusually small packet size: {packet_size} bytes")
        
        # Check for suspicious TTL values
        if ttl is not None:
            if ttl < 10:  # Very low TTL might indicate spoofing
                return ("suspicious_ttl", f"Suspicious TTL value: {ttl}")
        
        return None

    def _check_geographic_anomalies(self, packet_data: Dict) -> Optional[Tuple[str, str]]:
        """Check for geographic anomalies (placeholder for future implementation)."""
        # This could be extended with GeoIP databases
        # For now, just check for private IP ranges in public traffic
        # Note: This is disabled by default as it flags normal internet usage
        # Uncomment the lines below if you want to enable this check
        # src_ip = packet_data.get("src_ip", "")
        # dst_ip = packet_data.get("dst_ip", "")
        # 
        # if self._is_private_ip(src_ip) and not self._is_private_ip(dst_ip):
        #     return ("private_to_public", f"Private IP {src_ip} communicating with public IP {dst_ip}")
        
        return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is in private ranges."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            first = int(parts[0])
            second = int(parts[1])
            
            # Private IP ranges
            if first == 10:
                return True
            elif first == 172 and 16 <= second <= 31:
                return True
            elif first == 192 and second == 168:
                return True
            elif first == 127:
                return True
            return False
        except:
            return False

    def analyze(self, packet_data: Dict) -> Optional[Dict]:
        """Analyze packet metadata and return threat indicators."""
        # Convert PacketMetadata object to dict if needed
        if hasattr(packet_data, 'to_dict'):
            packet_data = packet_data.to_dict()
        
        # Run all analysis checks
        checks = [
            self._check_bad_ip,
            self._check_ja3_fingerprint,
            self._check_certificate_issues,
            self._check_suspicious_domain,
            self._check_port_anomalies,
            self._check_tls_anomalies,
            self._check_behavioral_anomalies,
            self._check_geographic_anomalies,
        ]
        
        for checker in checks:
            result = checker(packet_data)
            if result:
                indicator, reason = result
                return {
                    "indicator": indicator,
                    "reason": reason,
                    "timestamp": packet_data.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                    "src_ip": packet_data.get("src_ip", ""),
                    "dst_ip": packet_data.get("dst_ip", ""),
                    "confidence": self._calculate_confidence(indicator, packet_data)
                }
        
        return None

    def _calculate_confidence(self, indicator: str, packet_data: Dict) -> str:
        """Calculate confidence level for the threat indicator."""
        # High confidence indicators
        high_confidence = ["bad_ip", "ja3_blacklist", "cert_blacklisted_issuer", "cert_blacklisted_subject"]
        if indicator in high_confidence:
            return "high"
        
        # Medium confidence indicators
        medium_confidence = ["cert_expired", "suspicious_domain", "malware_port", "weak_tls_version"]
        if indicator in medium_confidence:
            return "medium"
        
        # Low confidence indicators
        return "low"

    def get_statistics(self) -> Dict:
        """Get analysis statistics."""
        return {
            "bad_ips_count": len(self.bad_ips),
            "ja3_blacklist_count": len(self.ja3_blacklist),
            "suspicious_domains_count": len(self.suspicious_domains),
            "cert_blacklist_count": len(self.cert_blacklist.get("issuers", set())) + len(self.cert_blacklist.get("subjects", set()))
        }
