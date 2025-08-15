import os
import json
import random
import time
import uuid
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path

# Known malicious IP ranges (documentation/test ranges)
DEFAULT_SOURCES = [
    "192.0.2.10", "192.0.2.11", "203.0.113.5", "198.51.100.77", "198.51.100.88"
]

# Target IPs (documentation ranges)
DEFAULT_DEST = "192.0.2.200"

# Suspicious domain patterns
SUSPICIOUS_DOMAINS = [
    "update.malware.com", "sync.bot.net", "backup.spy.org", "admin.hack.me",
    "api.steal.info", "control.malware.com", "remote.bot.net", "command.spy.org",
    "shell.hack.me", "malware-update.com", "bot-sync.net", "spy-backup.org"
]

# Legitimate domains for contrast
LEGITIMATE_DOMAINS = [
    "api.example.com", "updates.example.net", "cdn.safe.site", "office-sync.example.org",
    "mail.google.com", "www.github.com", "api.github.com", "cdnjs.cloudflare.com"
]

# JA3 fingerprints - malicious and legitimate
JA3_POOL_MALICIOUS = [
    "771,4865-4867-49195-49196,0-11-10,23-65281-0,29-23-24",
    "771,4866-4867,0-10-11,35-16,27-28-29",
    "771,4865,0-11,23-65281,29-23",
    "771,49195-49196,0-11-10,23-65281-0,29-23-24"
]

JA3_POOL_LEGITIMATE = [
    "771,4865-4867,0-10-11,35-16,27-28-29",
    "771,4865,0-11,23-65281,29-23",
    "771,49195-49196,0-11-10,23-65281-0,29-23-24",
    "771,4866-4867,0-10-11,35-16,27-28-29"
]

# Certificate issuers
CERT_ISSUERS = [
    "Let's Encrypt Authority X3",
    "DigiCert Inc",
    "GlobalSign nv-sa",
    "Amazon",
    "Google Trust Services LLC",
    "Self-Signed Certificate",
    "Malicious CA",
    "Fake Certificate Authority"
]

# TLS versions
TLS_VERSIONS = ["1.2", "1.3", "1.1", "1.0"]

# Cipher suites
CIPHER_SUITES = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256"
]


def random_ip():
    """Generate a random IP address, with bias towards known malicious ranges."""
    if random.random() < 0.7:
        return random.choice(DEFAULT_SOURCES)
    
    # Generate random IPs in documentation ranges
    blocks = [(192, 0, 2), (198, 51, 100), (203, 0, 113)]
    b = random.choice(blocks)
    return f"{b[0]}.{b[1]}.{b[2]}.{random.randint(1, 254)}"


def generate_malicious_event(base_time: datetime) -> dict:
    """Generate a malicious traffic event."""
    src = random_ip()
    dst = DEFAULT_DEST
    
    # Choose suspicious domain
    sni = random.choice(SUSPICIOUS_DOMAINS)
    
    # Use malicious JA3 fingerprint
    ja3 = random.choice(JA3_POOL_MALICIOUS)
    
    # Generate suspicious certificate
    cert_days = random.randint(-30, 0)  # Expired or near expiry
    cert_valid_to = (base_time + timedelta(days=cert_days)).isoformat() + "Z"
    issuer = random.choice(["Self-Signed Certificate", "Malicious CA", "Fake Certificate Authority"])
    
    # Generate event ID and packet data
    event_id = str(uuid.uuid4())
    packet_sizes = [random.randint(60, 150) for _ in range(random.randint(3, 6))]
    
    # Beacon-like timings
    ts0 = base_time + timedelta(seconds=random.randint(0, 240))
    timestamps = [(ts0 + timedelta(seconds=i*random.randint(15, 45))).isoformat() + "Z" 
                  for i in range(len(packet_sizes))]
    
    return {
        "event_id": event_id,
        "protocol": "TLS",
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": random.choice([443, 8443, 9443, 10443]),
        "sni": sni,
        "ja3": ja3,
        "tls_version": random.choice(TLS_VERSIONS),
        "cipher_suite": random.choice(CIPHER_SUITES),
        "cert_issuer": issuer,
        "cert_valid_to": cert_valid_to,
        "packet_sizes": packet_sizes,
        "packet_timestamps": timestamps,
        "threat_level": "high",
        "indicator": random.choice(["suspicious_domain", "cert_self_signed", "malicious_ja3"])
    }


def generate_legitimate_event(base_time: datetime) -> dict:
    """Generate a legitimate traffic event."""
    src = random_ip()
    dst = DEFAULT_DEST
    
    # Choose legitimate domain
    sni = random.choice(LEGITIMATE_DOMAINS)
    
    # Use legitimate JA3 fingerprint
    ja3 = random.choice(JA3_POOL_LEGITIMATE)
    
    # Generate legitimate certificate
    cert_days = random.randint(30, 365)  # Valid for future
    cert_valid_to = (base_time + timedelta(days=cert_days)).isoformat() + "Z"
    issuer = random.choice(["Let's Encrypt Authority X3", "DigiCert Inc", "GlobalSign nv-sa"])
    
    # Generate event ID and packet data
    event_id = str(uuid.uuid4())
    packet_sizes = [random.randint(200, 1500) for _ in range(random.randint(5, 10))]
    
    # Normal timings
    ts0 = base_time + timedelta(seconds=random.randint(0, 300))
    timestamps = [(ts0 + timedelta(seconds=i*random.randint(60, 300))).isoformat() + "Z" 
                  for i in range(len(packet_sizes))]
    
    return {
        "event_id": event_id,
        "protocol": "TLS",
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": 443,
        "sni": sni,
        "ja3": ja3,
        "tls_version": random.choice(["1.2", "1.3"]),
        "cipher_suite": random.choice(CIPHER_SUITES[:3]),  # Strong ciphers only
        "cert_issuer": issuer,
        "cert_valid_to": cert_valid_to,
        "packet_sizes": packet_sizes,
        "packet_timestamps": timestamps,
        "threat_level": "low",
        "indicator": "legitimate"
    }


def generate_events(count: int = 50, out_path: str = "data/simulated_flows.jsonl", 
                   malicious_ratio: float = 0.3) -> str:
    """Generate synthetic TLS flow events with configurable malicious ratio."""
    Path(os.path.dirname(out_path)).mkdir(parents=True, exist_ok=True)
    base_time = datetime.utcnow() - timedelta(minutes=5)
    
    malicious_count = int(count * malicious_ratio)
    legitimate_count = count - malicious_count
    
    with open(out_path, "w", encoding="utf-8") as f:
        # Generate malicious events
        for _ in range(malicious_count):
            event = generate_malicious_event(base_time)
            f.write(json.dumps(event) + "\n")
        
        # Generate legitimate events
        for _ in range(legitimate_count):
            event = generate_legitimate_event(base_time)
            f.write(json.dumps(event) + "\n")
    
    # console.print(f"[green]Generated {malicious_count} malicious and {legitimate_count} legitimate events[/]") # This line was removed as per the new_code
    return out_path


def generate_advanced_scenarios(out_path: str = "data/advanced_scenarios.jsonl") -> str:
    """Generate advanced attack scenarios for testing."""
    Path(os.path.dirname(out_path)).mkdir(parents=True, exist_ok=True)
    base_time = datetime.utcnow() - timedelta(minutes=10)
    
    scenarios = [
        # Command & Control communication
        {
            "scenario": "c2_communication",
            "description": "Beaconing behavior with regular intervals",
            "events": []
        },
        # Data exfiltration
        {
            "scenario": "data_exfiltration", 
            "description": "Large packet sizes, unusual ports",
            "events": []
        },
        # Certificate manipulation
        {
            "scenario": "cert_manipulation",
            "description": "Expired, self-signed, or suspicious certificates",
            "events": []
        }
    ]
    
    # Generate C2 scenario
    for i in range(10):
        event = generate_malicious_event(base_time)
        event["scenario"] = "c2_communication"
        event["dst_port"] = random.choice([8080, 8443, 9443])
        event["packet_sizes"] = [random.randint(80, 200) for _ in range(5)]
        # Regular intervals
        ts0 = base_time + timedelta(seconds=i*30)
        event["packet_timestamps"] = [ts0.isoformat() + "Z"]
        scenarios[0]["events"].append(event)
    
    # Generate data exfiltration scenario
    for i in range(5):
        event = generate_malicious_event(base_time)
        event["scenario"] = "data_exfiltration"
        event["packet_sizes"] = [random.randint(1000, 5000) for _ in range(3)]
        event["dst_port"] = random.choice([4444, 9000, 9001])
        scenarios[1]["events"].append(event)
    
    # Generate certificate manipulation scenario
    for i in range(8):
        event = generate_malicious_event(base_time)
        event["scenario"] = "cert_manipulation"
        event["cert_issuer"] = random.choice(["Self-Signed Certificate", "Malicious CA"])
        event["cert_valid_to"] = (base_time - timedelta(days=random.randint(1, 100))).isoformat() + "Z"
        scenarios[2]["events"].append(event)
    
    # Write scenarios to file
    with open(out_path, "w", encoding="utf-8") as f:
        for scenario in scenarios:
            f.write(json.dumps(scenario) + "\n")
    
    return out_path


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Generate synthetic encrypted traffic for testing")
    ap.add_argument("--count", type=int, default=50, help="Number of events to generate")
    ap.add_argument("--out", default="data/simulated_flows.jsonl", help="Output file path")
    ap.add_argument("--malicious-ratio", type=float, default=0.3, help="Ratio of malicious events (0.0-1.0)")
    ap.add_argument("--advanced", action="store_true", help="Generate advanced attack scenarios")
    
    args = ap.parse_args()
    
    if args.advanced:
        path = generate_advanced_scenarios(args.out)
        print(f"Generated advanced scenarios at {path}")
    else:
        path = generate_events(args.count, args.out, args.malicious_ratio)
        print(f"Generated {args.count} events at {path}")
