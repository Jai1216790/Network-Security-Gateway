ALLOWED_SOURCE_NETWORKS = [
    "0.0.0.0/0"  # Allows live traffic from all subnets during capture
]

ALLOWED_DESTINATION_NETWORKS = [
    "0.0.0.0/0"  # Allows destination routing across all subnets
]

ALLOWED_PROTOCOLS = [
    "TCP",
    "UDP",
    "ICMP"
]

ALLOWED_DESTINATION_PORTS = [
    22,
    53,
    80,
    443,
    3000,
    5000,
    8080       # Added common development & web ports to prevent false drops
]