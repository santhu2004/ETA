import os
import sys
import json
import argparse
import yaml
import signal
import time
from datetime import datetime, timedelta
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.prompt import Prompt, Confirm

from attacker_sim.simulate_attack import generate_events
from core.capture import get_capture_engine, ReplayCapture
from core.analysis import Analyzer
from core.mitigation import Mitigator
from core.logger import EventLogger

console = Console()

def load_config():
    with open("config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def ensure_dirs(paths_cfg):
    """Ensure all output directories exist."""
    for key in ("outputs_dir", "data_dir", "logs_dir", "state_dir", "exports_dir"):
        if key in paths_cfg:
            os.makedirs(paths_cfg[key], exist_ok=True)

def cmd_simulate(args):
    """Generate synthetic encrypted flow events."""
    cfg = load_config()
    ensure_dirs(cfg["paths"])
    
    # Use malicious_ratio if provided, otherwise default to 0.3
    malicious_ratio = getattr(args, 'malicious_ratio', 0.3)
    
    out = os.path.join(cfg["paths"]["data_dir"], "simulated_flows.jsonl")
    path = generate_events(args.count, out, malicious_ratio)
    
    console.print(f"[bold green]Generated[/] {args.count} synthetic TLS flows")
    console.print(f"[dim]Malicious ratio: {malicious_ratio:.1%}[/]")
    console.print(f"[dim]Output: {path}[/]")

def cmd_capture(args):
    """Start real-time packet capture and analysis."""
    cfg = load_config()
    ensure_dirs(cfg["paths"])
    
    # Initialize components
    try:
        # Get capture engine
        if args.replay:
            console.print("[yellow]Using replay mode with simulated data[/]")
            capt = ReplayCapture(os.path.join(cfg["paths"]["data_dir"], "simulated_flows.jsonl"))
            if not os.path.exists(capt.data_path):
                console.print("[red]No simulated data found. Run 'simulate' command first.[/]")
                return
        else:
            console.print(f"[green]Starting real-time capture on interface: {cfg.get('interface', 'auto')}[/]")
            capt = get_capture_engine(
                engine=args.engine,
                interface=cfg.get("interface"),
                filter=args.filter
            )
        
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
        
    except Exception as e:
        console.print(f"[red]Failed to initialize components: {e}[/]")
        return
    
    # Statistics
    total_packets = 0
    flagged_packets = 0
    start_time = time.time()
    
    # Signal handler for graceful shutdown
    def signal_handler(signum, frame):
        console.print("\n[yellow]Shutting down capture...[/]")
        if hasattr(capt, 'stop_capture'):
            capt.stop_capture()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        if not args.replay:
            capt.start_capture()
            console.print("[green]Capture started. Press Ctrl+C to stop.[/]")
        
        # Main capture loop
        with Live(
            Panel(f"[bold]Capturing packets...[/]\n"
                  f"Total: {total_packets} | Flagged: {flagged_packets} | "
                  f"Runtime: {time.time() - start_time:.1f}s", 
                  title="Encrypted Traffic Analysis"),
            refresh_per_second=2
        ) as live:
            
            while True:
                if args.replay:
                    # Replay mode - process all packets at once
                    for event in capt.stream():
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
                            
                            # Update display
                            live.update(
                                Panel(f"[bold]Capturing packets...[/]\n"
                                      f"Total: {total_packets} | Flagged: {flagged_packets} | "
                                      f"Runtime: {time.time() - start_time:.1f}s\n\n"
                                      f"[red]ALERT: {ip} → {indicator}[/]\n"
                                      f"Reason: {reason}\n"
                                      f"Confidence: {confidence}",
                                      title="Encrypted Traffic Analysis")
                            )
                    
                    break  # Exit after processing all replay data
                    
                else:
                    # Real-time mode
                    packet = capt.get_packet(timeout=1.0)
                    if packet:
                        total_packets += 1
                        packet_dict = packet.to_dict()
                        
                        result = analyzer.analyze(packet_dict)
                        
                        if result:
                            flagged_packets += 1
                            ip = packet_dict["src_ip"]
                            reason = result["reason"]
                            indicator = result["indicator"]
                            confidence = result.get("confidence", "medium")
                            
                            # Block IP
                            mitigator.block_ip(ip, reason=reason, confidence=confidence)
                            
                            # Log detection
                            logger.log(
                                src_ip=ip,
                                dst_ip=packet_dict.get("dst_ip", ""),
                                src_port=packet_dict.get("src_port"),
                                dst_port=packet_dict.get("dst_port"),
                                protocol=packet_dict.get("protocol"),
                                indicator=indicator,
                                reason=reason,
                                confidence=confidence,
                                action="blocked",
                                packet_size=packet_dict.get("packet_size"),
                                tls_sni=packet_dict.get("tls_sni"),
                                tls_version=packet_dict.get("tls_version"),
                                cert_issuer=packet_dict.get("cert_issuer"),
                                cert_subject=packet_dict.get("cert_subject"),
                                ja3_fingerprint=packet_dict.get("ja3_fingerprint")
                            )
                            
                            # Update display
                            live.update(
                                Panel(f"[bold]Capturing packets...[/]\n"
                                      f"Total: {total_packets} | Flagged: {flagged_packets} | "
                                      f"Runtime: {time.time() - start_time:.1f}s\n\n"
                                      f"[red]ALERT: {ip} → {indicator}[/]\n"
                                      f"Reason: {reason}\n"
                                      f"Confidence: {confidence}",
                                      title="Encrypted Traffic Analysis")
                            )
                    
                    # Update display periodically
                    if total_packets % 10 == 0:
                        live.update(
                            Panel(f"[bold]Capturing packets...[/]\n"
                                  f"Total: {total_packets} | Flagged: {flagged_packets} | "
                                  f"Runtime: {time.time() - start_time:.1f}s",
                                  title="Encrypted Traffic Analysis")
                        )
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Capture stopped by user[/]")
    except Exception as e:
        console.print(f"\n[red]Capture error: {e}[/]")
    finally:
        if not args.replay and hasattr(capt, 'stop_capture'):
            capt.stop_capture()
    
    # Final statistics
    runtime = time.time() - start_time
    console.print(f"\n[bold]Capture Summary:[/]")
    console.print(f"  Total packets processed: {total_packets}")
    console.print(f"  Packets flagged: {flagged_packets}")
    console.print(f"  Runtime: {runtime:.1f} seconds")
    if total_packets > 0:
        console.print(f"  Detection rate: {(flagged_packets/total_packets)*100:.2f}%")

def cmd_show_logs(args):
    cfg = load_config()
    logger = EventLogger(cfg["paths"]["logs_dir"])
    rows = logger.read_jsonl()
    if not rows:
        console.print("[yellow]No detections yet.[/]")
        return
    table = Table(title="Detections (latest first)")
    table.add_column("Time")
    table.add_column("Src IP")
    table.add_column("Dst IP")
    table.add_column("Indicator")
    table.add_column("Reason")
    table.add_column("Action")
    for rec in reversed(rows[-50:]):  # show last 50
        table.add_row(rec["ts"], rec["src_ip"], rec.get("dst_ip",""), rec["indicator"], rec["reason"], rec["action"])
    console.print(table)

def cmd_unblock(args):
    cfg = load_config()
    from core.mitigation import Mitigator
    m = Mitigator(cfg["paths"]["state_dir"], mode=cfg.get("mode","simulate"), block_duration_seconds=cfg.get("block_duration_seconds", 300))
    ok = m.unblock_ip(args.ip)
    if ok:
        console.print(f"[green]Unblocked[/] {args.ip} (simulation state updated).")

def cmd_list_blocks(args):
    """List all currently blocked IPs."""
    cfg = load_config()
    mitigator = Mitigator(
        state_dir=cfg["paths"]["state_dir"],
        mode=cfg.get("mode", "simulate"),
        block_duration_seconds=cfg.get("block_duration_seconds", 300)
    )
    
    blocks = mitigator.list_blocks()
    
    if not blocks:
        console.print("[yellow]No IPs are currently blocked.[/]")
        return
    
    # Create table
    table = Table(title=f"Blocked IPs ({len(blocks)} total)")
    table.add_column("IP Address", style="red")
    table.add_column("Reason", style="white")
    table.add_column("Confidence", style="green")
    table.add_column("Created", style="cyan")
    table.add_column("Expires", style="yellow")
    table.add_column("Block Count", style="magenta")
    
    for block in blocks:
        confidence_color = {
            "high": "red",
            "medium": "yellow",
            "low": "green"
        }.get(block.get("confidence", "medium"), "white")
        
        table.add_row(
            block["ip"],
            block.get("reason", "")[:40] + "..." if len(block.get("reason", "")) > 40 else block.get("reason", ""),
            f"[{confidence_color}]{block.get('confidence', 'unknown')}[/{confidence_color}]",
            block["created_at"][:19],
            block["expires_at"][:19],
            str(block.get("block_count", 1))
        )
    
    console.print(table)


def cmd_show_stats(args):
    """Show system statistics."""
    cfg = load_config()
    
    # Get analyzer stats
    analyzer = Analyzer(
        rules_paths={
            "bad_ips": cfg["paths"]["bad_ips"],
            "ja3_blacklist": cfg["paths"]["ja3_blacklist"],
            "suspicious_domains": cfg["paths"].get("suspicious_domains", ""),
            "cert_blacklist": cfg["paths"].get("cert_blacklist", "")
        },
        thresholds=cfg["thresholds"]
    )
    
    # Get mitigator stats
    mitigator = Mitigator(
        state_dir=cfg["paths"]["state_dir"],
        mode=cfg.get("mode", "simulate"),
        block_duration_seconds=cfg.get("block_duration_seconds", 300)
    )
    
    # Get logger stats
    logger = EventLogger(cfg["paths"]["logs_dir"])
    
    # Display statistics
    console.print(Panel.fit(
        f"[bold]System Statistics[/]\n\n"
        f"[cyan]Analysis Rules:[/]\n"
        f"  Bad IPs: {analyzer.get_statistics()['bad_ips_count']}\n"
        f"  JA3 Blacklist: {analyzer.get_statistics()['ja3_blacklist_count']}\n"
        f"  Suspicious Domains: {analyzer.get_statistics()['suspicious_domains_count']}\n\n"
        f"[cyan]Mitigation:[/]\n"
        f"  Total Blocked: {mitigator.get_statistics()['total_blocked']}\n"
        f"  High Confidence: {mitigator.get_statistics()['high_confidence']}\n"
        f"  Medium Confidence: {mitigator.get_statistics()['medium_confidence']}\n"
        f"  Low Confidence: {mitigator.get_statistics()['low_confidence']}\n"
        f"  Mode: {mitigator.get_statistics()['mode']}\n\n"
        f"[cyan]Logging:[/]\n"
        f"  Total Detections: {logger.get_statistics()['total_detections']}\n"
        f"  Last Updated: {logger.get_statistics()['last_updated'][:19]}",
        title="System Overview"
    ))


def cmd_export(args):
    """Export data in various formats."""
    cfg = load_config()
    ensure_dirs(cfg["paths"])
    
    if args.type == "blocks":
        mitigator = Mitigator(
            state_dir=cfg["paths"]["state_dir"],
            mode=cfg.get("mode", "simulate"),
            block_duration_seconds=cfg.get("block_duration_seconds", 300)
        )
        
        output = mitigator.export_blocks(format=args.format)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(cfg["paths"]["exports_dir"], f"blocks_export_{timestamp}.{args.format}")
        
        with open(output_file, "w") as f:
            f.write(output)
        
        console.print(f"[green]✓ Exported blocks to {output_file}[/]")
        
    elif args.type == "logs":
        logger = EventLogger(cfg["paths"]["logs_dir"])
        
        # Build filters
        filters = {}
        if args.hours:
            since = (datetime.utcnow() - timedelta(hours=args.hours)).isoformat() + "Z"
            filters["since"] = since
        
        output = logger.export_detections(format=args.format, filters=filters)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(cfg["paths"]["exports_dir"], f"logs_export_{timestamp}.{args.format}")
        
        with open(output_file, "w") as f:
            f.write(output)
        
        console.print(f"[green]✓ Exported logs to {output_file}[/]")

def main():
    ap = argparse.ArgumentParser(
        prog="encrypted-traffic-analysis",
        description="Advanced encrypted traffic analysis and threat detection system.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate test data
  encrypted-traffic-analysis simulate --count 100
  
  # Start real-time capture
  encrypted-traffic-analysis capture
  
  # Replay simulated data
  encrypted-traffic-analysis capture --replay
  
  # Show recent detections
  encrypted-traffic-analysis show-logs --limit 50
  
  # Show system statistics
  encrypted-traffic-analysis show-stats
        """
    )
    sub = ap.add_subparsers(dest="cmd", help="Available commands")

    sp = sub.add_parser("simulate", help="Generate synthetic encrypted flow events")
    sp.add_argument("--count", type=int, default=50)
    sp.add_argument("--malicious-ratio", type=float, default=0.3, help="Ratio of malicious flows to generate")
    sp.set_defaults(func=cmd_simulate)

    cp = sub.add_parser("capture", help="Start packet capture and analysis")
    cp.add_argument("--replay", action="store_true", help="Use replay mode with simulated data")
    cp.add_argument("--engine", choices=["auto", "scapy", "pyshark"], default="auto", 
                   help="Packet capture engine to use")
    cp.add_argument("--filter", default="tcp port 443", help="BPF filter for packet capture")
    cp.set_defaults(func=cmd_capture)

    sl = sub.add_parser("show-logs", help="Show recent detections")
    sl.set_defaults(func=cmd_show_logs)

    ub = sub.add_parser("unblock", help="Unblock an IP (simulation state)")
    ub.add_argument("--ip", required=True)
    ub.set_defaults(func=cmd_unblock)

    lb = sub.add_parser("list-blocks", help="List blocked IPs (simulation state)")
    lb.set_defaults(func=cmd_list_blocks)

    # Show stats command
    ss = sub.add_parser("show-stats", help="Show system statistics")
    ss.set_defaults(func=cmd_show_stats)

    # Export command
    ex = sub.add_parser("export", help="Export data in various formats")
    ex.add_argument("--type", choices=["blocks", "logs"], required=True, help="Type of data to export")
    ex.add_argument("--format", choices=["json", "csv", "txt"], default="json", help="Export format")
    ex.add_argument("--hours", type=int, help="For logs: export from last N hours")
    ex.set_defaults(func=cmd_export)

    args = ap.parse_args()
    if not hasattr(args, "func"):
        ap.print_help()
        sys.exit(1)
    
    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/]")
        if hasattr(args, 'debug') and args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
