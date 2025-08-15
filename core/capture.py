import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Generator
from datetime import datetime
import threading
import queue

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, TLS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

import psutil


class PacketMetadata:
    """Container for extracted packet metadata from encrypted traffic."""
    
    def __init__(self):
        self.src_ip: str = ""
        self.dst_ip: str = ""
        self.src_port: int = 0
        self.dst_port: int = 0
        self.protocol: str = ""
        self.timestamp: datetime = datetime.utcnow()
        self.packet_size: int = 0
        self.tls_sni: Optional[str] = None
        self.tls_version: Optional[str] = None
        self.tls_cipher_suite: Optional[str] = None
        self.cert_issuer: Optional[str] = None
        self.cert_subject: Optional[str] = None
        self.cert_valid_from: Optional[str] = None
        self.cert_valid_to: Optional[str] = None
        self.ja3_fingerprint: Optional[str] = None
        self.tcp_flags: Optional[str] = None
        self.ttl: Optional[int] = None
        
    def to_dict(self) -> Dict:
        """Convert metadata to dictionary format."""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "timestamp": self.timestamp.isoformat() + "Z",
            "packet_size": self.packet_size,
            "tls_sni": self.tls_sni,
            "tls_version": self.tls_version,
            "tls_cipher_suite": self.tls_cipher_suite,
            "cert_issuer": self.cert_issuer,
            "cert_subject": self.cert_subject,
            "cert_valid_from": self.cert_valid_from,
            "cert_valid_to": self.cert_valid_to,
            "ja3_fingerprint": self.ja3_fingerprint,
            "tcp_flags": self.tcp_flags,
            "ttl": self.ttl
        }


class ScapyCapture:
    """Real-time packet capture using Scapy."""
    
    def __init__(self, interface: str = None, filter: str = "tcp port 443 or tcp port 993 or tcp port 995"):
        self.interface = interface or self._get_default_interface()
        self.filter = filter
        self.packet_queue = queue.Queue(maxsize=1000)
        self.is_capturing = False
        self.capture_thread = None
        
    def _get_default_interface(self) -> str:
        """Get the default network interface."""
        try:
            # Get the first non-loopback interface using psutil
            interfaces = psutil.net_if_addrs()
            for iface in interfaces:
                if iface != 'lo' and not iface.startswith('docker'):
                    return iface
            return 'eth0'  # fallback
        except:
            return 'eth0'
    
    def _extract_tls_metadata(self, packet) -> Optional[Dict]:
        """Extract TLS metadata from packet if available."""
        metadata = {}
        
        # Check for TLS layer
        if TLS in packet:
            tls_layer = packet[TLS]
            
            # Extract TLS version
            if hasattr(tls_layer, 'version'):
                metadata['tls_version'] = str(tls_layer.version)
            
            # Extract SNI from Client Hello
            if hasattr(tls_layer, 'extensions'):
                for ext in tls_layer.extensions:
                    if hasattr(ext, 'type') and ext.type == 0:  # SNI extension
                        if hasattr(ext, 'server_names'):
                            metadata['tls_sni'] = ext.server_names[0].decode('utf-8', errors='ignore')
        
        return metadata
    
    def _packet_callback(self, packet):
        """Callback function for each captured packet."""
        try:
            metadata = PacketMetadata()
            
            # Basic IP information
            if IP in packet:
                metadata.src_ip = packet[IP].src
                metadata.dst_ip = packet[IP].dst
                metadata.ttl = packet[IP].ttl
                metadata.packet_size = len(packet)
                metadata.timestamp = datetime.utcnow()
            
            # TCP/UDP information
            if TCP in packet:
                metadata.protocol = "TCP"
                metadata.src_port = packet[TCP].sport
                metadata.dst_port = packet[TCP].dport
                metadata.tcp_flags = str(packet[TCP].flags)
            elif UDP in packet:
                metadata.protocol = "UDP"
                metadata.src_port = packet[UDP].sport
                metadata.dst_port = packet[UDP].dport
            
            # Extract TLS metadata
            tls_data = self._extract_tls_metadata(packet)
            if tls_data:
                for key, value in tls_data.items():
                    setattr(metadata, key, value)
            
            # Add to queue if not full
            try:
                self.packet_queue.put_nowait(metadata)
            except queue.Full:
                # Drop oldest packet if queue is full
                try:
                    self.packet_queue.get_nowait()
                    self.packet_queue.put_nowait(metadata)
                except queue.Empty:
                    pass
                    
        except Exception as e:
            # Log error but continue capturing
            print(f"Error processing packet: {e}")
    
    def start_capture(self):
        """Start packet capture in a separate thread."""
        if self.is_capturing:
            return
            
        self.is_capturing = True
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True
        )
        self.capture_thread.start()
    
    def _capture_loop(self):
        """Main capture loop."""
        try:
            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=self._packet_callback,
                store=0,  # Don't store packets in memory
                stop_filter=lambda _: not self.is_capturing
            )
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            self.is_capturing = False
    
    def stop_capture(self):
        """Stop packet capture."""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=1)
    
    def get_packet(self, timeout: float = 1.0) -> Optional[PacketMetadata]:
        """Get next packet from queue."""
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def get_packets(self, count: int = 10, timeout: float = 1.0) -> List[PacketMetadata]:
        """Get multiple packets from queue."""
        packets = []
        for _ in range(count):
            packet = self.get_packet(timeout)
            if packet:
                packets.append(packet)
            else:
                break
        return packets


class PySharkCapture:
    """Real-time packet capture using PyShark (Wireshark)."""
    
    def __init__(self, interface: str = None, filter: str = "tcp.port == 443"):
        self.interface = interface or self._get_default_interface()
        self.filter = filter
        self.capture = None
        self.packet_queue = queue.Queue(maxsize=1000)
        self.is_capturing = False
        self.capture_thread = None
    
    def _get_default_interface(self) -> str:
        """Get the default network interface."""
        try:
            # Get the first non-loopback interface using psutil
            interfaces = psutil.net_if_addrs()
            for iface in interfaces:
                if iface != 'lo' and not iface.startswith('docker'):
                    return iface
            return 'eth0'  # fallback
        except:
            return 'eth0'
    
    def _extract_tls_metadata(self, packet) -> Dict:
        """Extract TLS metadata from PyShark packet."""
        metadata = {}
        
        try:
            # Extract TLS information
            if hasattr(packet, 'tls'):
                tls = packet.tls
                if hasattr(tls, 'handshake_extensions_server_name'):
                    metadata['tls_sni'] = tls.handshake_extensions_server_name
                if hasattr(tls, 'handshake_version'):
                    metadata['tls_version'] = tls.handshake_version
                if hasattr(tls, 'handshake_ciphersuite'):
                    metadata['tls_cipher_suite'] = tls.handshake_ciphersuite
            
            # Extract certificate information if available
            if hasattr(packet, 'ssl'):
                ssl = packet.ssl
                if hasattr(ssl, 'handshake_cert_issuer'):
                    metadata['cert_issuer'] = ssl.handshake_cert_issuer
                if hasattr(ssl, 'handshake_cert_subject'):
                    metadata['cert_subject'] = ssl.handshake_cert_subject
                if hasattr(ssl, 'handshake_cert_validity_notafter'):
                    metadata['cert_valid_to'] = ssl.handshake_cert_validity_notafter
                if hasattr(ssl, 'handshake_cert_validity_notbefore'):
                    metadata['cert_valid_from'] = ssl.handshake_cert_validity_notbefore
                    
        except Exception as e:
            # Continue if TLS extraction fails
            pass
            
        return metadata
    
    def _packet_callback(self, packet):
        """Callback for each captured packet."""
        try:
            metadata = PacketMetadata()
            
            # Basic packet information
            if hasattr(packet, 'ip'):
                metadata.src_ip = packet.ip.src
                metadata.dst_ip = packet.ip.dst
                metadata.ttl = int(packet.ip.ttl) if hasattr(packet.ip, 'ttl') else None
            
            if hasattr(packet, 'tcp'):
                metadata.protocol = "TCP"
                metadata.src_port = int(packet.tcp.srcport)
                metadata.dst_port = int(packet.tcp.dstport)
                metadata.tcp_flags = packet.tcp.flags if hasattr(packet.tcp, 'flags') else None
            elif hasattr(packet, 'udp'):
                metadata.protocol = "UDP"
                metadata.src_port = int(packet.udp.srcport)
                metadata.dst_port = int(packet.udp.dstport)
            
            metadata.packet_size = int(packet.length) if hasattr(packet, 'length') else 0
            metadata.timestamp = datetime.utcnow()
            
            # Extract TLS metadata
            tls_data = self._extract_tls_metadata(packet)
            for key, value in tls_data.items():
                setattr(metadata, key, value)
            
            # Add to queue
            try:
                self.packet_queue.put_nowait(metadata)
            except queue.Full:
                try:
                    self.packet_queue.get_nowait()
                    self.packet_queue.put_nowait(metadata)
                except queue.Empty:
                    pass
                    
        except Exception as e:
            print(f"Error processing PyShark packet: {e}")
    
    def start_capture(self):
        """Start packet capture."""
        if self.is_capturing:
            return
            
        try:
            self.capture = pyshark.LiveCapture(
                interface=self.interface,
                output_file=None,
                bpf_filter=self.filter
            )
            
            self.is_capturing = True
            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                daemon=True
            )
            self.capture_thread.start()
            
        except Exception as e:
            print(f"Failed to start PyShark capture: {e}")
    
    def _capture_loop(self):
        """Main capture loop for PyShark."""
        try:
            for packet in self.capture.sniff_continuously():
                if not self.is_capturing:
                    break
                self._packet_callback(packet)
        except Exception as e:
            print(f"PyShark capture error: {e}")
        finally:
            self.is_capturing = False
    
    def stop_capture(self):
        """Stop packet capture."""
        self.is_capturing = False
        if self.capture:
            self.capture.close()
        if self.capture_thread:
            self.capture_thread.join(timeout=1)
    
    def get_packet(self, timeout: float = 1.0) -> Optional[PacketMetadata]:
        """Get next packet from queue."""
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def get_packets(self, count: int = 10, timeout: float = 1.0) -> List[PacketMetadata]:
        """Get multiple packets from queue."""
        packets = []
        for _ in range(count):
            packet = self.get_packet(timeout)
            if packet:
                packets.append(packet)
            else:
                break
        return packets


class ReplayCapture:
    """Reads synthetic flow events from JSONL produced by the simulator."""
    
    def __init__(self, data_path: str):
        self.data_path = data_path

    def stream(self):
        if not os.path.exists(self.data_path):
            raise FileNotFoundError(f"No data found at {self.data_path}. Run simulator first.")
        with open(self.data_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                yield json.loads(line)


def get_capture_engine(engine: str = "auto", interface: str = None, filter: str = None) -> object:
    """Factory function to get the best available capture engine."""
    
    if engine == "scapy" and SCAPY_AVAILABLE:
        return ScapyCapture(interface, filter)
    elif engine == "pyshark" and PYSHARK_AVAILABLE:
        return PySharkCapture(interface, filter)
    elif engine == "auto":
        if SCAPY_AVAILABLE:
            return ScapyCapture(interface, filter)
        elif PYSHARK_AVAILABLE:
            return PySharkCapture(interface, filter)
        else:
            raise RuntimeError("No packet capture engines available. Install Scapy or PyShark.")
    else:
        raise RuntimeError(f"Capture engine '{engine}' not available. Available: {_get_available_engines()}")


def _get_available_engines() -> List[str]:
    """Get list of available capture engines."""
    engines = []
    if SCAPY_AVAILABLE:
        engines.append("scapy")
    if PYSHARK_AVAILABLE:
        engines.append("pyshark")
    return engines
