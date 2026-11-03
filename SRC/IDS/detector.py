import time
import re, os

# =========================
# DETECT PORT SCAN
# =========================

port_activity = {}
port_scan_alerted = set()

PORT_SCAN_THRESHOLD = 5
PORT_SCAN_TIME_WINDOW = 60


def record_port_activity(source_ip, destination_port, current_time):

    if source_ip not in port_activity:
        port_activity[source_ip]=[]

    port_activity[source_ip].append((destination_port, current_time))


def remove_old_activity(source_ip, current_time):

    if source_ip in port_activity:

        port_activity[source_ip] = [
             activity for activity in port_activity[source_ip]
             if current_time - activity[1]<=PORT_SCAN_TIME_WINDOW 
        ]

def detect_port_scan(source_ip,destination_port, current_time = None):

    if current_time is None:
        current_time = time.time()
     

    if source_ip not in port_activity:
        port_activity[source_ip] = []

    remove_old_activity(source_ip, current_time)

    record_port_activity(
        source_ip,
        destination_port,
        current_time
    )


    unique_ports = set()

    for activity in port_activity[source_ip]:
        unique_ports.add(activity[0])

    
    if len(unique_ports)>=PORT_SCAN_THRESHOLD:
        if source_ip not in port_scan_alerted:
            port_scan_alerted.add(source_ip)
            return "ALERT: Possible Port Scan"
    
    return "Normal"

# =========================
# BRUTE FORCE ACTIVITY
# =========================

brute_force_activity = {}

BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_TIME_WINDOW = 60

def record_failed_attempts(source_ip, new_attempt_time):
    if source_ip not in brute_force_activity:
        brute_force_activity[source_ip] = []

    brute_force_activity[source_ip].append(new_attempt_time)


def remove_old_failed_attempts(source_ip, new_attempt_time):
    if source_ip in brute_force_activity:
        brute_force_activity[source_ip] = [
            previous_attempt_time
            for previous_attempt_time in brute_force_activity[source_ip]
            if new_attempt_time-previous_attempt_time<=BRUTE_FORCE_TIME_WINDOW
        ]

def detect_brute_force(source_ip, destination_port, connection_status, new_attempt_time = None):
    if new_attempt_time is None:
        new_attempt_time = time.time()

    if destination_port!=22:
        return "NORMAL"

    remove_old_failed_attempts(source_ip, new_attempt_time)

    if connection_status == "FAILED":
        record_failed_attempts(source_ip,new_attempt_time)

    if source_ip in brute_force_activity:
        if len(brute_force_activity[source_ip])>=BRUTE_FORCE_THRESHOLD:
            return "ALERT: Possible Brute Force"

    return "NORMAL"

connection_activity = {}

CONNECTION_FLOOD_THRESHOLD =  10
CONNECTION_FLOOD_TIME_WINDOW = 60

def record_connection(source_ip, new_connection_time):
    if source_ip not in connection_activity:
        connection_activity[source_ip]= []
    connection_activity[source_ip].append(new_connection_time)

def remove_old_connections(source_ip, new_connection_time):
    if source_ip in connection_activity:
        connection_activity[source_ip] = [
            previous_connection_time
            for previous_connection_time in connection_activity[source_ip]
            if new_connection_time - previous_connection_time <= CONNECTION_FLOOD_TIME_WINDOW
        ]

def detect_connection_flood(source_ip, new_connection_time = None):
    if new_connection_time == None:
        new_connection_time = time.time()

    record_connection(source_ip, new_connection_time)

    remove_old_connections(source_ip, new_connection_time)

    if len(connection_activity[source_ip]) >= CONNECTION_FLOOD_THRESHOLD:
        return "ALERT: Possible connection flood"

    return "NORMAL"

auth_log_position = os.path.getsize("/var/log/auth.log")

def check_ssh_failed_attempts():

    global auth_log_position

    try:
        with open("/var/log/auth.log", "r") as log_file:

            log_file.seek(auth_log_position)

            new_lines = log_file.readlines()

            auth_log_position = log_file.tell()

    except PermissionError:
        return

    for line in new_lines:

        if "Failed password" not in line:
            continue

        match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

        if match is None:
            continue

        source_ip = match.group(1)

        brute_force_result = detect_brute_force(
            source_ip,
            22,
            "FAILED"
        )

        if brute_force_result.startswith("ALERT"):
            log_security_event(
                source_ip,
                "Brute Force",
                brute_force_result
            )

            print("IDS ALERT:", brute_force_result)

# =========================
# TRAFFIC ANOMALY DETECTION
# =========================
traffic_activity = []
traffic_anomaly_alerted = False
TRAFFIC_ANOMALY_THRESHOLD = 100
TRAFFIC_ANOMALY_TIME_WINDOW = 60


def record_traffic(new_packet_time):
    traffic_activity.append(new_packet_time)


def remove_old_traffic(new_packet_time):
    global traffic_activity

    traffic_activity = [
        previous_packet_time
        for previous_packet_time in traffic_activity
        if new_packet_time - previous_packet_time <= TRAFFIC_ANOMALY_TIME_WINDOW
    ]


def detect_traffic_anomaly(new_packet_time=None):
    global traffic_anomaly_alerted

    if new_packet_time is None:
        new_packet_time = time.time()

    remove_old_traffic(new_packet_time)
    
    record_traffic(new_packet_time)

    if len(traffic_activity) >= TRAFFIC_ANOMALY_THRESHOLD:
        if not traffic_anomaly_alerted:
            traffic_anomaly_alerted = True
            return "ALERT: Traffic Anomaly"

    return "NORMAL"

# =========================
# ALERT / EVENT LOGGING
# =========================

def log_security_event(source_ip, detection_type, alert_message):
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")

    with open("IDS_security_events.log", "a") as log_file:
        log_file.write(
            current_time
            + " | Source IP: "
            + source_ip
            + " | Detection: "
            + detection_type
            + " | "
            + alert_message
            + "\n"
        )