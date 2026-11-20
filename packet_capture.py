import time
import json
import random
import socket
import ipaddress
import threading
import urllib.request
from scapy.all import sniff, IP, TCP, UDP, ICMP

from SRC.Firewall.rules import (
    ALLOWED_SOURCE_NETWORKS,
    ALLOWED_DESTINATION_PORTS
)
from SRC.IPS.prevention import is_blocked

EVALUATE_URL = "http://127.0.0.1:5000/api/evaluate_packet"

_EXTERNAL_IP_POOL = []
_CURRENT_INTERNAL_IP = None
_CURRENT_IP_HITS = 0


def _pick_fresh_internal_ip():
    """Finds an unblocked host IP from ALLOWED_SOURCE_NETWORKS"""
    non_loopback_nets = [
        ipaddress.ip_network(net)
        for net in ALLOWED_SOURCE_NETWORKS
        if not ipaddress.ip_network(net).is_loopback and net != "0.0.0.0/0"
    ]
    if not non_loopback_nets:
        return "192.168.1.50"

    chosen_net = random.choice(non_loopback_nets)
    max_usable = max(3, chosen_net.num_addresses - 2)
    for _ in range(30):
        offset = random.randint(2, max_usable)
        candidate = str(chosen_net.network_address + offset)
        if not is_blocked(candidate):
            return candidate
    return str(chosen_net.network_address + random.randint(2, max_usable))


def generate_dynamic_source_ip():
    """Dynamically derives internal hosts from ALLOWED_SOURCE_NETWORKS or bounded external IPs"""
    global _CURRENT_INTERNAL_IP, _CURRENT_IP_HITS

    if random.random() < 0.85:
        if (
            _CURRENT_INTERNAL_IP is None
            or _CURRENT_IP_HITS >= 11
            or is_blocked(_CURRENT_INTERNAL_IP)
        ):
            _CURRENT_INTERNAL_IP = _pick_fresh_internal_ip()
            _CURRENT_IP_HITS = 0

        _CURRENT_IP_HITS += 1
        return _CURRENT_INTERNAL_IP

    while len(_EXTERNAL_IP_POOL) < 12:
        candidate = ipaddress.IPv4Address(random.randint(0x0B000001, 0xDF000000))
        if (
            not candidate.is_private
            and not candidate.is_loopback
            and not candidate.is_multicast
            and not candidate.is_reserved
            and all(candidate not in ipaddress.ip_network(net) for net in ALLOWED_SOURCE_NETWORKS)
        ):
            _EXTERNAL_IP_POOL.append(str(candidate))

    return random.choice(_EXTERNAL_IP_POOL)


def forward_packet_to_gateway(src_ip, dst_ip, protocol, dst_port, flags):
    """Forwards captured packet metadata to main.py for Firewall -> IDS -> IPS evaluation"""
    payload = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "dst_port": dst_port,
        "flags": flags
    }
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            EVALUATE_URL,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=0.3) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            print(f"[{result.get('stage', 'NSG')}] {src_ip} -> Port {dst_port}/{protocol} => {result.get('decision')}")
    except Exception:
        pass


def background_traffic_generator():
    """Sends gradual UDP probes (~1-2 events/sec) across allowed and restricted ports"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    allowed_ports = [p for p in ALLOWED_DESTINATION_PORTS if p != 5000]
    restricted_ports = [21, 23, 25, 3306]

    while True:
        burst_size = random.randint(1, 3)
        for _ in range(burst_size):
            if allowed_ports and random.random() < 0.85:
                target_port = random.choice(allowed_ports + [22, 22])
            else:
                target_port = random.choice(restricted_ports)
            try:
                sock.sendto(b"NSG_LIVE_PROBE", ("127.0.0.1", target_port))
            except Exception:
                pass
            time.sleep(random.uniform(0.35, 0.75))
        time.sleep(random.uniform(1.5, 3.0))


def process_packet(packet):
    """Captures live packet headers on lo and forwards them to main.py"""
    if IP not in packet:
        return

    if TCP in packet and (
        packet[TCP].sport == 5000 or packet[TCP].dport == 5000
    ):
        return

    destination_ip = packet[IP].dst
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

    raw_src = packet[IP].src
    active_ip = generate_dynamic_source_ip() if raw_src == "127.0.0.1" else raw_src

    forward_packet_to_gateway(active_ip, destination_ip, protocol, destination_port, flags)


def start_sniffer():
    print("============================================================")
    print(" Network Security Gateway (NSG) Packet Sniffer Active (WSL)")
    print(" Interface: lo | Forwarding to: http://127.0.0.1:5000")
    print("============================================================")

    traffic_thread = threading.Thread(target=background_traffic_generator, daemon=True)
    traffic_thread.start()

    sniff(
        iface="lo",
        filter="not port 5000",
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_sniffer()