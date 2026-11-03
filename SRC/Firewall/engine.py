import ipaddress

from .rules import (
  ALLOWED_SOURCE_NETWORKS,
  ALLOWED_DESTINATION_NETWORKS,
  ALLOWED_PROTOCOLS,
  ALLOWED_DESTINATION_PORTS)

from SRC.IPS.prevention import is_blocked

def check_source_ip(source_ip):

    source_address = ipaddress.ip_address(source_ip)

    for src_network in ALLOWED_SOURCE_NETWORKS:
        allowed_src_networks = ipaddress.ip_network(src_network)

        if source_address in allowed_src_networks:
            return "ALLOW"

    return "DROP"

def check_dest_ip(dest_ip):

    dest_address = ipaddress.ip_address(dest_ip)

    for dest_network in ALLOWED_DESTINATION_NETWORKS:
        allowed_dest_networks = ipaddress.ip_network(dest_network)

        if dest_address in allowed_dest_networks:
            return "ALLOW"

    return "DROP"

def check_destination_port(destination_port):

    if destination_port in ALLOWED_DESTINATION_PORTS:
        return "ALLOW"

    return "DROP"

def check_protocol(protocol):
    if protocol in ALLOWED_PROTOCOLS:
        return "ALLOW"
    else:
        return "DROP"

def check_packet(source_ip, dest_ip, protocol, destination_port):

    if is_blocked(source_ip):
        return "DROP"

    source_decision = check_source_ip(source_ip)
    destination_decision = check_dest_ip(dest_ip)
    protocol_decision = check_protocol(protocol)

    if protocol == "ICMP":
        destination_port_decision = "ALLOW"
    else:
        destination_port_decision = check_destination_port(destination_port)

    if (source_decision == "ALLOW"
            and destination_decision == "ALLOW"
            and protocol_decision == "ALLOW"
            and destination_port_decision == "ALLOW"):

        return "ALLOW"

    return "DROP"