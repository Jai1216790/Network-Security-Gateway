import logging
from datetime import datetime
from collections import deque
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# In-memory circular buffer for recent security events (keeps last 100)
recent_events = deque(maxlen=100)
blocked_ips = {}
system_metrics = {
    "total_events": 0,
    "ids_events": 0,
    "ips_events": 0,
    "ips_premium": False
}


@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/log_event', methods=['POST'])
def receive_vm_log():
    """Endpoint called by packet_capture.py to post live network events"""
    data = request.get_json() or {}
    
    src_ip = data.get("src_ip", "0.0.0.0")
    event_type = data.get("type", "IDS")      # "IDS" or "IPS"
    severity = data.get("severity", "Low")    # "Low", "Medium", "High"
    details = data.get("details", "Traffic activity logged")
    action = data.get("action", "Passed")     # "Passed", "Alert", "Blocked"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    system_metrics["total_events"] += 1
    if event_type == "IDS":
        system_metrics["ids_events"] += 1
    elif event_type == "IPS":
        system_metrics["ips_events"] += 1

    if action == "Blocked":
        blocked_ips[src_ip] = data.get("reason", details)

    recent_events.appendleft({
        "time": timestamp,
        "ip": src_ip,
        "type": event_type,
        "severity": severity,
        "details": details
    })

    return jsonify({"status": "logged", "timestamp": timestamp}), 200


@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Endpoint polled by dashboard.js every 2 seconds"""
    formatted_blocked = [
        {"ip": ip, "reason": reason} for ip, reason in blocked_ips.items()
    ]
    active_threats = len([e for e in recent_events if e.get("severity") == "High"])

    return jsonify({
        "total_events": system_metrics["total_events"],
        "ids_events": system_metrics["ids_events"],
        "ips_events": system_metrics["ips_events"],
        "blocked_count": len(formatted_blocked),
        "active_threats": active_threats,
        "ips_premium": system_metrics["ips_premium"],
        "events": list(recent_events),
        "blocked_ips": formatted_blocked
    })


@app.route('/api/unblock', methods=['POST'])
def unblock_ip():
    """Endpoint to unblock an IP from the dashboard UI"""
    data = request.get_json() or {}
    target_ip = data.get('ip')
    if target_ip in blocked_ips:
        del blocked_ips[target_ip]
        return jsonify({"status": "success", "message": f"Unblocked {target_ip}"})
    return jsonify({"status": "error", "message": "IP not found"}), 404


@app.route('/api/upgrade-ips', methods=['POST'])
def upgrade_ips():
    """Endpoint to toggle IPS Premium mode"""
    system_metrics["ips_premium"] = True
    return jsonify({"status": "success", "message": "IPS Premium enabled."})


def run_dashboard():
    """Starts the Flask app on port 5000 with quiet logging for thread integration"""
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)


if __name__ == '__main__':
    run_dashboard()