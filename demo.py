#!/usr/bin/env python3
"""
Demo script for Encrypted Traffic Analysis System
This script demonstrates the main features of the system.
"""

import os
import sys
import time
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from attacker_sim.simulate_attack import generate_events
from core.capture import ReplayCapture
from core.analysis import Analyzer
from core.mitigation import Mitigator
from core.logger import EventLogger


def run_demo():
    """Run a complete demonstration of the system."""
    print("🚀 Encrypted Traffic Analysis System - Demo")
    print("=" * 50)
    
    # Ensure output directories exist
    os.makedirs("outputs/data", exist_ok=True)
    os.makedirs("outputs/logs", exist_ok=True)
    os.makedirs("outputs/state", exist_ok=True)
    os.makedirs("outputs/exports", exist_ok=True)
    
    print("\n📊 Step 1: Generating synthetic attack data...")
    generate_events(50, "outputs/data/simulated_flows.jsonl")
    print("✅ Generated 50 synthetic TLS flows")
    
    print("\n🔍 Step 2: Initializing analysis components...")
    analyzer = Analyzer(
        rules_paths={
            "bad_ips": "rules/bad_ips.txt",
            "ja3_blacklist": "rules/ja3_blacklist.json",
            "suspicious_domains": "rules/suspicious_domains.txt",
            "cert_blacklist": "rules/cert_blacklist.json"
        },
        thresholds={
            "beacon_min_events": 4,
            "beacon_max_jitter_ms": 2500
        }
    )
    
    mitigator = Mitigator(
        state_dir="outputs/state",
        mode="simulate",
        block_duration_seconds=300
    )
    
    logger = EventLogger("outputs/logs")
    print("✅ Components initialized")
    
    print("\n📡 Step 3: Running packet analysis...")
    capture = ReplayCapture("outputs/data/simulated_flows.jsonl")
    
    total_packets = 0
    flagged_packets = 0
    
    for event in capture.stream():
        total_packets += 1
        result = analyzer.analyze(event)
        
        if result:
            flagged_packets += 1
            ip = event["src_ip"]
            reason = result["reason"]
            indicator = result["indicator"]
            confidence = result.get("confidence", "medium")
            
            # Block IP
            mitigator.block_ip(ip, reason=reason, confidence=confidence)
            
            # Log detection
            logger.log(
                src_ip=ip,
                dst_ip=event.get("dst_ip", ""),
                src_port=event.get("src_port"),
                dst_port=event.get("dst_port", 443),
                protocol="TLS",
                indicator=indicator,
                reason=reason,
                confidence=confidence,
                action="blocked",
                packet_size=event.get("packet_size"),
                tls_sni=event.get("sni"),
                ja3_fingerprint=event.get("ja3")
            )
            
            print(f"🚨 ALERT: {ip} → {indicator} ({confidence} confidence)")
            print(f"   Reason: {reason}")
    
    print(f"\n✅ Analysis complete!")
    print(f"   Total packets: {total_packets}")
    print(f"   Threats detected: {flagged_packets}")
    print(f"   Detection rate: {(flagged_packets/total_packets)*100:.1f}%")
    
    print("\n📈 Step 4: System statistics...")
    stats = mitigator.get_statistics()
    print(f"   Total blocked IPs: {stats['total_blocked']}")
    print(f"   High confidence: {stats['high_confidence']}")
    print(f"   Medium confidence: {stats['medium_confidence']}")
    print(f"   Low confidence: {stats['low_confidence']}")
    
    print("\n📁 Step 5: Generated files...")
    print(f"   Data: outputs/data/simulated_flows.jsonl")
    print(f"   Logs: outputs/logs/detections.jsonl")
    print(f"   State: outputs/state/blocked_ips.json")
    
    print("\n🎉 Demo completed successfully!")
    print("\nTo explore further:")
    print("  python -m cli.main show-stats")
    print("  python -m cli.main list-blocks")
    print("  python -m cli.main show-logs")
    print("  python -m cli.main export --type blocks --format json")


if __name__ == "__main__":
    try:
        run_demo()
    except KeyboardInterrupt:
        print("\n\n⏹️ Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
