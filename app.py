"""
NETPULSE — Network Security Monitoring Platform
Author: Rohit Kumar Reddy Sakam
GitHub: https://github.com/RohitKumarReddySakam
Version: 1.0.0

Passive network flow monitoring for detecting anomalous traffic,
threat intelligence correlation, and security alerting.
"""

from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta
import os
import json
import uuid
import threading
import time
import logging
import random
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
sio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_recent_flows_cache = []
_cache_lock = threading.Lock()
MAX_CACHE = 500


# ─── Models ───────────────────────────────────────────────────────
class NetworkFlow(db.Model):
    __tablename__ = "network_flows"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    bytes_sent = db.Column(db.Integer, default=0)
    bytes_recv = db.Column(db.Integer, default=0)
    packets = db.Column(db.Integer, default=0)
    duration_ms = db.Column(db.Integer, default=0)
    geo_src_country = db.Column(db.String(50))
    geo_dst_country = db.Column(db.String(50))
    risk_score = db.Column(db.Float, default=0.0)
    threat_match = db.Column(db.Boolean, default=False)
    flow_start = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "protocol": self.protocol, "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv, "packets": self.packets,
            "risk_score": self.risk_score, "threat_match": self.threat_match,
            "flow_start": self.flow_start.isoformat() if self.flow_start else None,
        }


class NetworkAlert(db.Model):
    __tablename__ = "network_alerts"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    title = db.Column(db.String(300))
    description = db.Column(db.Text)
    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))
    mitre_tactic = db.Column(db.String(100))
    status = db.Column(db.String(30), default="open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "alert_type": self.alert_type, "severity": self.severity,
            "title": self.title, "description": self.description,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "mitre_tactic": self.mitre_tactic, "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class KnownHost(db.Model):
    __tablename__ = "known_hosts"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address = db.Column(db.String(50), unique=True)
    hostname = db.Column(db.String(200))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    bytes_total = db.Column(db.Integer, default=0)
    is_internal = db.Column(db.Boolean, default=False)
    risk_level = db.Column(db.String(20), default="low")

    def to_dict(self):
        return {
            "id": self.id, "ip_address": self.ip_address, "hostname": self.hostname,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "bytes_total": self.bytes_total, "is_internal": self.is_internal,
            "risk_level": self.risk_level,
        }


# ─── Routes — Pages ───────────────────────────────────────────────
@app.route("/")
def dashboard():
    total_flows = NetworkFlow.query.count()
    open_alerts = NetworkAlert.query.filter_by(status="open").count()
    critical_alerts = NetworkAlert.query.filter_by(severity="CRITICAL").count()
    known_hosts = KnownHost.query.count()
    recent_alerts = NetworkAlert.query.order_by(NetworkAlert.created_at.desc()).limit(5).all()
    return render_template("index.html",
        total_flows=total_flows, open_alerts=open_alerts,
        critical_alerts=critical_alerts, known_hosts=known_hosts,
        recent_alerts=recent_alerts)


@app.route("/flows")
def flows_page():
    flows = NetworkFlow.query.order_by(NetworkFlow.flow_start.desc()).limit(200).all()
    return render_template("flows.html", flows=flows)


@app.route("/alerts")
def alerts_page():
    alerts = NetworkAlert.query.order_by(NetworkAlert.created_at.desc()).all()
    return render_template("alerts.html", alerts=alerts)


# ─── Routes — API ─────────────────────────────────────────────────
@app.route("/api/flow", methods=["POST"])
def ingest_flow():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400

    from core.flow_analyzer import analyze_flow, calculate_risk_score
    from core.threat_feeds import check_ip

    # Check threat feeds
    src_threat = check_ip(data.get("src_ip", ""))
    dst_threat = check_ip(data.get("dst_ip", ""))
    threat_match = src_threat.get("malicious") or dst_threat.get("malicious") or src_threat.get("tor") or dst_threat.get("tor")

    risk_score = calculate_risk_score(data, threat_match)

    flow = NetworkFlow(
        src_ip=data.get("src_ip", ""),
        dst_ip=data.get("dst_ip", ""),
        src_port=data.get("src_port"),
        dst_port=data.get("dst_port"),
        protocol=data.get("protocol", "TCP"),
        bytes_sent=data.get("bytes_sent", 0),
        bytes_recv=data.get("bytes_recv", 0),
        packets=data.get("packets", 0),
        duration_ms=data.get("duration_ms", 0),
        risk_score=risk_score,
        threat_match=bool(threat_match),
    )
    db.session.add(flow)
    db.session.commit()

    # Update cache
    with _cache_lock:
        _recent_flows_cache.append(data)
        if len(_recent_flows_cache) > MAX_CACHE:
            _recent_flows_cache.pop(0)

    # Update known hosts
    for ip, internal in [(data.get("src_ip"), True), (data.get("dst_ip"), False)]:
        if ip:
            host = KnownHost.query.filter_by(ip_address=ip).first()
            if host:
                host.last_seen = datetime.utcnow()
                host.bytes_total += data.get("bytes_sent", 0)
            else:
                host = KnownHost(
                    ip_address=ip,
                    is_internal=ip.startswith(("10.", "192.168.", "172.16.")),
                    bytes_total=data.get("bytes_sent", 0),
                )
                db.session.add(host)

    # Analyze for anomalies
    with _cache_lock:
        cache_copy = list(_recent_flows_cache[-100:])

    anomalies = analyze_flow(data, cache_copy)

    # Threat feed alerts
    for threat_info in [src_threat, dst_threat]:
        if threat_info.get("malicious") or threat_info.get("tor"):
            anomalies.append({
                "alert_type": "threat_feed_match",
                "severity": "HIGH" if threat_info.get("malicious") else "MEDIUM",
                "title": f"Threat Feed Match: {threat_info.get('ip', '')}",
                "description": threat_info.get("reason", "IP matches threat feed"),
                "mitre_tactic": "Command and Control",
                "src_ip": data.get("src_ip", ""),
                "dst_ip": data.get("dst_ip", ""),
            })

    created_alerts = []
    for anomaly in anomalies:
        alert = NetworkAlert(
            alert_type=anomaly["alert_type"],
            severity=anomaly["severity"],
            title=anomaly["title"],
            description=anomaly["description"],
            src_ip=anomaly.get("src_ip", ""),
            dst_ip=anomaly.get("dst_ip", ""),
            mitre_tactic=anomaly.get("mitre_tactic", ""),
        )
        db.session.add(alert)
        db.session.commit()
        created_alerts.append(alert.to_dict())
        sio.emit("new_alert", alert.to_dict())

    db.session.commit()
    return jsonify({"flow_id": flow.id, "risk_score": risk_score, "alerts": len(created_alerts)}), 201


@app.route("/api/flows")
def get_flows():
    src = request.args.get("src_ip")
    protocol = request.args.get("protocol")
    q = NetworkFlow.query
    if src:
        q = q.filter_by(src_ip=src)
    if protocol:
        q = q.filter_by(protocol=protocol.upper())
    flows = q.order_by(NetworkFlow.flow_start.desc()).limit(100).all()
    return jsonify({"flows": [f.to_dict() for f in flows]})


@app.route("/api/alerts")
def get_alerts():
    alerts = NetworkAlert.query.order_by(NetworkAlert.created_at.desc()).limit(100).all()
    return jsonify({"alerts": [a.to_dict() for a in alerts]})


@app.route("/api/alert/<alert_id>", methods=["PATCH"])
def update_alert(alert_id):
    alert = NetworkAlert.query.get_or_404(alert_id)
    data = request.get_json()
    if "status" in data:
        alert.status = data["status"]
    db.session.commit()
    return jsonify(alert.to_dict())


@app.route("/api/stats")
def get_stats():
    from core.traffic_stats import compute_stats
    flows = NetworkFlow.query.order_by(NetworkFlow.flow_start.desc()).limit(1000).all()
    flow_dicts = [f.to_dict() for f in flows]
    stats = compute_stats(flow_dicts)
    stats["open_alerts"] = NetworkAlert.query.filter_by(status="open").count()
    stats["total_alerts"] = NetworkAlert.query.count()
    stats["known_hosts"] = KnownHost.query.count()
    return jsonify(stats)


@app.route("/api/hosts")
def get_hosts():
    hosts = KnownHost.query.order_by(KnownHost.last_seen.desc()).limit(100).all()
    return jsonify({"hosts": [h.to_dict() for h in hosts]})


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "version": "1.0.0", "timestamp": datetime.utcnow().isoformat()})


@sio.on("connect")
def on_connect():
    logger.info("Client connected")


def _seed_demo_flows():
    """Seed demo network flows and alerts."""
    ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "10.0.0.5", "10.0.0.10"]
    ext_ips = ["8.8.8.8", "1.1.1.1", "185.220.101.45", "45.33.32.156"]
    protocols = ["TCP", "UDP", "TCP", "TCP"]

    for i in range(30):
        src = random.choice(ips)
        dst = random.choice(ext_ips)
        flow = NetworkFlow(
            src_ip=src,
            dst_ip=dst,
            src_port=random.randint(40000, 60000),
            dst_port=random.choice([80, 443, 22, 53, 8080]),
            protocol=random.choice(protocols),
            bytes_sent=random.randint(100, 5_000_000),
            bytes_recv=random.randint(100, 2_000_000),
            packets=random.randint(10, 1000),
            risk_score=random.uniform(0, 0.5),
        )
        db.session.add(flow)

    # Seed an alert
    alert = NetworkAlert(
        alert_type="port_scan",
        severity="HIGH",
        title="Port Scan Detected from 185.220.101.45",
        description="Source scanned 18 distinct ports",
        src_ip="185.220.101.45",
        dst_ip="192.168.1.10",
        mitre_tactic="Reconnaissance",
    )
    db.session.add(alert)
    db.session.commit()


def create_app():
    with app.app_context():
        db.create_all()
        if NetworkFlow.query.count() == 0:
            _seed_demo_flows()
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", 5005))
    sio.run(app, host="0.0.0.0", port=port, debug=False)
