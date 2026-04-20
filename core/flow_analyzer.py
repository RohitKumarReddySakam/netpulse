"""
Network flow analyzer — detects anomalies in network traffic patterns.
Works on submitted flow records (passive analysis, no packet capture).
"""
import logging
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


def analyze_flow(flow: dict, recent_flows: list) -> list:
    """
    Analyze a new flow against recent flows to detect anomalies.
    Returns list of alert dicts.
    """
    alerts = []

    src_ip = flow.get("src_ip", "")
    dst_ip = flow.get("dst_ip", "")
    dst_port = flow.get("dst_port")
    protocol = flow.get("protocol", "").upper()
    bytes_sent = flow.get("bytes_sent", 0)

    # Port scan detection: many distinct ports from same source in last 60 seconds
    if recent_flows:
        recent_same_src = [
            f for f in recent_flows
            if f.get("src_ip") == src_ip
        ]
        unique_ports = {f.get("dst_port") for f in recent_same_src if f.get("dst_port")}
        if len(unique_ports) > 15:
            alerts.append({
                "alert_type": "port_scan",
                "severity": "HIGH",
                "title": f"Port Scan Detected from {src_ip}",
                "description": f"Source {src_ip} scanned {len(unique_ports)} distinct ports",
                "mitre_tactic": "Reconnaissance",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
            })

    # Large data exfiltration
    if bytes_sent > 50_000_000:  # 50MB in a single flow
        alerts.append({
            "alert_type": "data_exfiltration",
            "severity": "HIGH",
            "title": f"Large Data Transfer from {src_ip}",
            "description": f"{src_ip} transferred {bytes_sent / 1_000_000:.1f} MB to {dst_ip}",
            "mitre_tactic": "Exfiltration",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        })

    # Suspicious ports
    dangerous_ports = {4444, 5555, 1337, 31337, 4899, 6666}
    if dst_port in dangerous_ports:
        alerts.append({
            "alert_type": "suspicious_port",
            "severity": "CRITICAL",
            "title": f"Connection to Suspicious Port {dst_port}",
            "description": f"{src_ip} connected to {dst_ip}:{dst_port} — commonly used by malware/C2",
            "mitre_tactic": "Command and Control",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        })

    # Beaconing: regular connections to same external IP
    if recent_flows:
        same_dst_flows = [f for f in recent_flows if f.get("dst_ip") == dst_ip and f.get("src_ip") == src_ip]
        if len(same_dst_flows) >= 8:
            alerts.append({
                "alert_type": "beaconing",
                "severity": "MEDIUM",
                "title": f"Possible C2 Beaconing to {dst_ip}",
                "description": f"{src_ip} has made {len(same_dst_flows)} connections to {dst_ip} — possible C2 beacon",
                "mitre_tactic": "Command and Control",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
            })

    return alerts


def calculate_risk_score(flow: dict, threat_match: bool = False) -> float:
    """Score a flow 0-1 based on risk indicators."""
    score = 0.0
    dst_port = flow.get("dst_port", 0)
    bytes_sent = flow.get("bytes_sent", 0)

    if dst_port in (4444, 5555, 1337, 31337):
        score += 0.8
    elif dst_port in (445, 3389, 23, 21):
        score += 0.3

    if bytes_sent > 100_000_000:
        score += 0.5
    elif bytes_sent > 10_000_000:
        score += 0.2

    if threat_match:
        score += 0.6

    return min(round(score, 2), 1.0)


def detect_lateral_movement(flows: list) -> list:
    """Detect internal-to-internal scanning patterns."""
    alerts = []
    src_to_dst = defaultdict(set)
    internal_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "192.168.")

    for flow in flows:
        src = flow.get("src_ip", "")
        dst = flow.get("dst_ip", "")
        if any(src.startswith(p) for p in internal_prefixes) and any(dst.startswith(p) for p in internal_prefixes):
            src_to_dst[src].add(dst)

    for src, dsts in src_to_dst.items():
        if len(dsts) > 10:
            alerts.append({
                "alert_type": "lateral_movement",
                "severity": "HIGH",
                "title": f"Lateral Movement from {src}",
                "description": f"Internal host {src} connecting to {len(dsts)} internal hosts",
                "mitre_tactic": "Lateral Movement",
                "src_ip": src,
                "dst_ip": ",".join(list(dsts)[:5]),
            })

    return alerts
