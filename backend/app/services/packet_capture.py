import threading
import time

from collections import defaultdict, deque

from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, get_if_addr

from app.core.database import SessionLocal
from app.models.traffic import Traffic

from app.services.alerts import create_security_alert


# Network interface
CAPTURE_INTERFACE = "Wi-Fi"

# Port scan detection configuration
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW = 60

# Capture state
_sniffer = None
_capture_lock = threading.Lock()
_scan_lock = threading.Lock()

_packets_captured = 0
_last_error = None
_local_ip = None

# Store incoming TCP SYN requests by source IP
_scan_attempts = defaultdict(deque)

# Prevent repeated alerts within the detection window
_scan_alerted_until = {}


def detect_incoming_port_scan(source_ip, destination_port):
    """
    Detect incoming TCP SYN requests targeting
    10 or more unique destination ports within 60 seconds.
    """

    current_time = time.monotonic()

    with _scan_lock:

        attempts = _scan_attempts[source_ip]

        # Remove requests older than 60 seconds
        while attempts and current_time - attempts[0][0] > PORT_SCAN_WINDOW:
            attempts.popleft()

        # Record the new connection attempt
        attempts.append((current_time, destination_port))

        # Count unique destination ports
        unique_ports = {
            port for timestamp, port in attempts
        }

        # Check whether the source has already triggered an alert
        if current_time < _scan_alerted_until.get(source_ip, 0):
            return None

        if len(unique_ports) >= PORT_SCAN_THRESHOLD:

            _scan_alerted_until[source_ip] = (
                current_time + PORT_SCAN_WINDOW
            )

            return {
                "is_port_scan": True,
                "scan_type": "rapid_port_scan",
                "severity": "HIGH",
                "source_ip": source_ip,
                "unique_ports_detected": len(unique_ports),
                "threshold": PORT_SCAN_THRESHOLD,
                "window_seconds": PORT_SCAN_WINDOW
            }

    return None


def process_packet(packet):
    """
    Extract IPv4 packet information,
    identify direction and save it to SQLite.
    """

    global _packets_captured, _last_error

    if IP not in packet:
        return

    ip_layer = packet[IP]

    source_ip = ip_layer.src
    destination_ip = ip_layer.dst

    source_port = None
    destination_port = None

    # Identify protocol
    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    else:
        protocol = str(ip_layer.proto)

    # Identify direction
    if source_ip == _local_ip and destination_ip != _local_ip:
        direction = "OUTBOUND"

    elif destination_ip == _local_ip and source_ip != _local_ip:
        direction = "INBOUND"

    else:
        direction = "UNKNOWN"

    # Only count incoming TCP SYN requests.
    # SYN = 1 and ACK = 0.
    is_syn_request = (
        TCP in packet
        and int(packet[TCP].flags) & 0x12 == 0x02
    )

    packet_size = len(packet)

    db = SessionLocal()

    try:

        new_traffic = Traffic(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            packet_size=packet_size,
            direction=direction,
            status="normal"
        )

        db.add(new_traffic)
        db.commit()

        # Run capture-specific port scan detection
        if (
            direction == "INBOUND"
            and is_syn_request
            and destination_port is not None
        ):

            detection_result = detect_incoming_port_scan(
                source_ip,
                destination_port
            )

            if detection_result:

                new_traffic.status = "suspicious"

                db.commit()

                create_security_alert(
                    db,
                    detection_result
                )

        _packets_captured += 1
        _last_error = None

    except Exception as error:

        db.rollback()
        _last_error = str(error)

    finally:
        db.close()


def start_capture():
    """
    Start background packet capture.
    """

    global _sniffer, _local_ip

    with _capture_lock:

        if _sniffer is not None and _sniffer.running:
            return {
                "message": "Packet capture is already running",
                "status": "running"
            }

        try:

            _local_ip = get_if_addr(CAPTURE_INTERFACE)

            if not _local_ip or _local_ip == "0.0.0.0":
                raise RuntimeError(
                    "Could not identify the Wi-Fi IPv4 address"
                )

            _sniffer = AsyncSniffer(
                iface=CAPTURE_INTERFACE,
                filter="ip",
                prn=process_packet,
                store=False
            )

            _sniffer.start()

            return {
                "message": "Packet capture started successfully",
                "status": "running",
                "interface": CAPTURE_INTERFACE,
                "local_ip": _local_ip
            }

        except Exception as error:

            _sniffer = None

            raise RuntimeError(
                f"Unable to start packet capture: {error}"
            )


def stop_capture():
    """
    Stop background packet capture.
    """

    global _sniffer

    with _capture_lock:

        if _sniffer is None or not _sniffer.running:
            return {
                "message": "Packet capture is already stopped",
                "status": "stopped"
            }

        try:

            _sniffer.stop()
            _sniffer = None

            return {
                "message": "Packet capture stopped successfully",
                "status": "stopped"
            }

        except Exception as error:

            raise RuntimeError(
                f"Unable to stop packet capture: {error}"
            )


def get_capture_status():
    """
    Return current packet capture information.
    """

    running = (
        _sniffer is not None
        and _sniffer.running
    )

    return {
        "status": "running" if running else "stopped",
        "interface": CAPTURE_INTERFACE,
        "local_ip": _local_ip,
        "packets_captured": _packets_captured,
        "last_error": _last_error
    }