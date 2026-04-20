"""Tests for NETPULSE flow analyzer, threat feeds, and traffic stats"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.flow_analyzer import analyze_flow, calculate_risk_score
from core.threat_feeds import check_ip, check_domain
from core.traffic_stats import compute_stats


# ─── Flow Analyzer ────────────────────────────────────────────────

def test_port_scan_detected():
    """16 unique destination ports from same source should trigger port scan alert."""
    base = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.5", "protocol": "TCP",
            "bytes_sent": 100, "bytes_recv": 50, "dst_port": 80}
    history = [{"src_ip": "10.0.0.1", "dst_ip": "192.168.1.5", "dst_port": p,
                "bytes_sent": 100, "protocol": "TCP"} for p in range(1, 17)]
    alerts = analyze_flow(base, history)
    assert any(a["alert_type"] == "port_scan" for a in alerts)


def test_large_transfer_detected():
    """60MB transfer should trigger data exfiltration alert."""
    flow = {"src_ip": "192.168.1.10", "dst_ip": "45.33.32.156", "protocol": "TCP",
            "bytes_sent": 60_000_000, "bytes_recv": 1000, "dst_port": 443}
    alerts = analyze_flow(flow, [])
    assert any(a["alert_type"] == "large_transfer" for a in alerts)


def test_suspicious_port_detected():
    """Traffic to port 4444 (Metasploit default) should trigger alert."""
    flow = {"src_ip": "192.168.1.10", "dst_ip": "1.2.3.4", "protocol": "TCP",
            "bytes_sent": 500, "bytes_recv": 200, "dst_port": 4444}
    alerts = analyze_flow(flow, [])
    assert any(a["alert_type"] == "suspicious_port" for a in alerts)


def test_beaconing_detected():
    """8+ connections to same dst should trigger beaconing alert."""
    flow = {"src_ip": "192.168.1.10", "dst_ip": "evil.c2.com", "protocol": "TCP",
            "bytes_sent": 200, "bytes_recv": 100, "dst_port": 443}
    history = [{"src_ip": "192.168.1.10", "dst_ip": "evil.c2.com", "dst_port": 443,
                "bytes_sent": 200, "protocol": "TCP"} for _ in range(8)]
    alerts = analyze_flow(flow, history)
    assert any(a["alert_type"] == "beaconing" for a in alerts)


def test_benign_flow_no_alert():
    flow = {"src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "protocol": "UDP",
            "bytes_sent": 512, "bytes_recv": 512, "dst_port": 53}
    alerts = analyze_flow(flow, [])
    assert len(alerts) == 0


# ─── Risk Score ───────────────────────────────────────────────────

def test_risk_score_threat_match_high():
    flow = {"dst_port": 80, "bytes_sent": 1000}
    score = calculate_risk_score(flow, threat_match=True)
    assert score >= 0.6


def test_risk_score_benign_low():
    flow = {"dst_port": 443, "bytes_sent": 2000}
    score = calculate_risk_score(flow, threat_match=False)
    assert score <= 0.3


def test_risk_score_suspicious_port():
    flow = {"dst_port": 4444, "bytes_sent": 1000}
    score = calculate_risk_score(flow, threat_match=False)
    assert score >= 0.5


# ─── Threat Feeds ─────────────────────────────────────────────────

def test_tor_exit_detected():
    result = check_ip("185.220.101.45")
    assert result.get("tor") is True


def test_malicious_ip_detected():
    result = check_ip("91.108.4.1")
    assert result.get("malicious") is True or result.get("tor") is True or not result.get("clean")


def test_benign_ip_clean():
    result = check_ip("8.8.8.8")
    assert not result.get("malicious")
    assert not result.get("tor")


def test_malicious_domain_detected():
    result = check_domain("malware-traffic.net")
    assert result.get("malicious") is True


def test_benign_domain_clean():
    result = check_domain("google.com")
    assert not result.get("malicious")


# ─── Traffic Stats ────────────────────────────────────────────────

def test_compute_stats_empty():
    stats = compute_stats([])
    assert stats["total_flows"] == 0
    assert stats["total_bytes"] == 0


def test_compute_stats_basic():
    flows = [
        {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "protocol": "TCP",
         "bytes_sent": 1000, "bytes_recv": 500, "dst_port": 443},
        {"src_ip": "10.0.0.2", "dst_ip": "1.1.1.1", "protocol": "UDP",
         "bytes_sent": 200, "bytes_recv": 100, "dst_port": 53},
    ]
    stats = compute_stats(flows)
    assert stats["total_flows"] == 2
    assert stats["total_bytes"] == 1800
    assert len(stats["top_talkers"]) > 0
    assert "TCP" in stats["protocol_dist"] or "UDP" in stats["protocol_dist"]
