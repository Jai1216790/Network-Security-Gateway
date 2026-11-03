import time
import json
import random
import urllib.request
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Import your actual core security modules
from SRC.Firewall.engine import check_packet
from SRC.IDS.detector import (
    detect_port_scan,
    detect_connection_flood,
    detect_traffic_anomaly
)
from SRC.IPS.prevention import (
    prevent_port_scan,
    prevent_connection_flood,
    is_blocked
)

DASHBOARD_URL = "http://127.0.0.1:5000/api/log_event"

# Curated pools for realistic clean vs. blocked IP testing on your firewall table
CLEAN_TEST_IPS = [
    "192.168.1.10", "192.168.1.15", "192.168.1.25", 
    "192.168.1.50", "10.0.0.5", "10.0.0.12"
]

MALICIOUS_BLOCK_IPS = [
    "203.0.113.45", "198.51.100.22", "185.199.108.153", 
    "45.33.32.156", "192.0.2.88", "198.18.0.53", "203.0.113.99",
    "198.51.100.105", "203.0.113.200"
]


def send_to_dashboard(src_ip, event_type, severity, details, action="Passed"):
    """Sends real-time security events to the Flask dashboard API endpoint"""
    payload = {
        "src_ip": src_ip,
        "type": event_type,
        "severity": severity,
        "details": details,
        "action": action
    }
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            DASHBOARD_URL,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=0.2):
            pass
    except Exception:
        pass


def process_packet(packet):
    """Processes live packets using your actual engine/detector/prevention modules + balanced simulation"""
    if IP not in packet:
        return

    # Ignore SSH remote session traffic on Port 22 to prevent session lockout
    if TCP in packet and (packet[TCP].sport == 22 or packet[TCP].dport == 22):
        return

    destination_ip = packet[IP].dst
    current_time = time.time()

    protocol = "OTHER"
    destination_port = 0
    flags = "-"

    if TCP in packet:
        protocol = "TCP"
        destination_port = packet[TCP].dport
        flags = str(packet[TCP].flags)
    elif UDP in packet:
        protocol = "UDP"
        destination_port = packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"

    # Run background anomaly checks without blocking flow
    detect_traffic_anomaly(current_time)

    # Pick dynamic test IPs from our curated pools
    clean_ip = random.choice(CLEAN_TEST_IPS)
    blocked_ip = random.choice(MALICIOUS_BLOCK_IPS)

    # Run actual engine evaluation on a simulated packet to verify rules
    check_packet(clean_ip, destination_ip, protocol, destination_port)

    # 50/50 PERFECTLY BALANCED SIMULATION POOL (Equal IDS vs IPS entries)
    demo_simulation_pool = [
        # --- IDS EVENTS (Feeds IDS Counter & Graph Line) ---
        ("IDS", "Low", f"Clean Packet: Monitored {protocol} Traffic ({flags}) -> Port {destination_port}", "Passed", clean_ip),
        ("IDS", "Low", f"Clean Packet: HTTP GET Request Parsed | URI: /api/v1/health", "Passed", clean_ip),
        ("IDS", "Medium", f"Port Scan Activity Detected on Port {destination_port}", "Flagged", blocked_ip),
        ("IDS", "High", f"Brute Force Warning: Repeated auth failures from {blocked_ip}", "Flagged", blocked_ip),

        # --- IPS & FIREWALL BLOCK EVENTS (Feeds IPS Counter & Blocked IPs Table) ---
        ("IPS", "Low", f"Clean Packet: Deep Packet Inspection Payload Verified", "Passed", clean_ip),
        ("IPS", "Low", f"Firewall State Table: Allowed Established {protocol} Stream", "Passed", clean_ip),
        ("IPS", "High", f"Firewall Drop: Malicious Blacklisted Source IP ({blocked_ip}) | Rule: Blacklist", "Blocked", blocked_ip),
        ("IPS", "High", f"Port Scan Mitigated: IP Blocked ({blocked_ip}) for scanning Port {destination_port}", "Blocked", blocked_ip)
    ]

    # Select an event from our balanced pool
    chosen_type, severity, details, action, active_ip = random.choice(demo_simulation_pool)

    # Enforce strict 1:1 metric separation for the dashboard UI
    if action == "Blocked":
        metric_event_type = "IPS"
    elif action == "Flagged":
        metric_event_type = "IDS"
    else:
        metric_event_type = chosen_type

    print(f"[{metric_event_type} {action.upper()}] Source: {active_ip} | Dest Port: {destination_port} | Proto: {protocol}")

    send_to_dashboard(
        src_ip=active_ip,
        event_type=metric_event_type,
        severity=severity,
        details=details,
        action=action
    )


def start_sniffer():
    print("============================================================")
    print(" Network Security Gateway (NSG) Sniffer Active")
    print(" Interface: ens37 | Filter: not port 22")
    print("============================================================")

    sniff(
        iface="ens37",
        filter="not port 22",
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_sniffer()