import time
import subprocess

from SRC.IDS.detector import (detect_port_scan, detect_brute_force, detect_connection_flood, detect_traffic_anomaly)
 

blocked_ips = set()

def block_ip(source_ip):
    blocked_ips.add(source_ip)
    subprocess.run([
        "nft",
        "add",
        "element",
        "inet",
        "nsg_firewall",
        "blocked_ips",
        "{",
        source_ip,
        "}"
    ])
    return "IP Blocked"

def unblock_ip(source_ip):
    if source_ip in blocked_ips:
        blocked_ips.remove(source_ip)
        return "IP Unblocked"

    return "IP not found"

def is_blocked(source_ip):
    return source_ip in blocked_ips

def prevent_port_scan(source_ip, destination_port, current_time):
    detection_result = detect_port_scan(
        source_ip,
        destination_port,
        current_time
    )

    if detection_result.startswith("ALERT"):
        block_ip(source_ip)
        log_ips_event(
            source_ip,
            "Port Scan",
            "IP Blocked"
        )
        return detection_result, "IPS: IP Blocked"

    return detection_result, "IPS: No Action"


def prevent_brute_force(
    source_ip,
    destination_port,
    connection_status,
    attempt_time
):
    detection_result = detect_brute_force(
        source_ip,
        destination_port,
        connection_status,
        attempt_time
    )

    if detection_result.startswith("ALERT"):
        block_ip(source_ip)
        log_ips_event(
            source_ip,
            "Brute Force",
            "IP Blocked"
        )
        return detection_result, "IPS: IP Blocked"

    return detection_result, "IPS: No Action"

def prevent_connection_flood(source_ip, connection_time):
    detection_result = detect_connection_flood(
        source_ip,
        connection_time
    )

    if detection_result.startswith("ALERT"):
        block_ip(source_ip)
        log_ips_event(
            source_ip,
            "Connection Flood",
            "IP Blocked"
        )
        return detection_result, "IPS: IP Blocked"

    return detection_result, "IPS: No Action"

 
def log_ips_event(source_ip, attack_type, action):
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")

    with open("IPS_security_events.log", "a") as log_file:
        log_file.write(
            current_time
            + " | Source IP: "
            + source_ip
            + " | Attack: "
            + attack_type
            + " | Action: "
            + action
            + "\n"
        )