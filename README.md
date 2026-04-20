<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=28&duration=3000&pause=1000&color=64FFDA&center=true&vCenter=true&width=750&lines=NETPULSE;Network+Security+Monitoring+Platform;Port+Scan+%7C+Beaconing+%7C+Exfiltration;Passive+Flow+Analysis+%7C+Threat+Intel" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)](https://attack.mitre.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

> **Passive network flow monitoring — detect port scans, C2 beaconing, data exfiltration, and lateral movement in real time.**

<br/>

[![Detection](https://img.shields.io/badge/Detections-6_Anomaly_Types-64ffda?style=flat-square)](.)
[![ThreatIntel](https://img.shields.io/badge/Threat_Intel-TOR_%2B_Malicious_IPs-64ffda?style=flat-square)](.)
[![Passive](https://img.shields.io/badge/Mode-Passive_Only-22c55e?style=flat-square)](.)
[![NoAPIKey](https://img.shields.io/badge/API_Keys-None_Required-22c55e?style=flat-square)](.)

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🎯 Problem Statement

Network-layer visibility is the **last line of defense** when endpoint agents fail. Malware beaconing, lateral movement, and data exfiltration all leave clear network traces. NETPULSE provides:

- **Passive flow analysis** — no active scanning, no traffic injection
- **Multi-vector anomaly detection** — 6 distinct attack patterns
- **Local threat intelligence** — TOR exit nodes + malicious IPs, no API keys required
- **Real-time WebSocket alerting** with MITRE ATT&CK tactic mapping
- **Host inventory** with automatic internal/external classification

| Feature | Details |
|---------|---------|
| **Anomaly Detections** | Port scan, beaconing, large transfer, lateral movement, suspicious ports, TOR |
| **Suspicious Ports** | 4444, 5555, 1337, 31337, 6666, 9001, 9030 |
| **Threat Intel** | Local TOR ranges + malicious IP lists (no API keys) |
| **Risk Scoring** | Composite 0.0–1.0 per flow |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🏗️ Architecture

```
Network Flow Source (NetFlow / sFlow / agent / manual)
                │  POST /api/flow
                ▼
┌──────────────────────────────────────────────┐
│            Flow Ingestion                     │
│  Threat feed lookup │ Risk score │ Host update│
└──────────────────┬───────────────────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
┌───────────────┐    ┌──────────────────┐
│ Flow Analyzer │    │  Threat Feeds    │
│ Port scan     │    │  TOR exit ranges │
│ Beaconing     │    │  Malicious IPs   │
│ Large transfer│    │  Malicious domains│
│ Lateral move  │    │  (local, no API) │
└───────┬───────┘    └──────────┬───────┘
        └──────────┬────────────┘
                   │
        ┌──────────▼──────────┐
        │   Alert Engine      │
        │   MITRE mapping     │
        │   WebSocket emit    │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │  Dashboard + API    │
        │  Flow table         │
        │  Traffic stats      │
        └─────────────────────┘
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔍 Detection Logic

| Detection | Trigger | MITRE |
|-----------|---------|-------|
| **Port Scan** | Source hits > 15 unique dst ports | Reconnaissance T1046 |
| **Beaconing** | Same src→dst ≥ 8 connections in cache | C2 T1071 |
| **Large Transfer** | Single flow > 50MB bytes_sent | Exfiltration T1048 |
| **Suspicious Port** | Dst port in [4444,5555,1337,31337…] | C2 T1571 |
| **Lateral Movement** | Internal→Internal + [22,445,3389,5985] | Lateral T1021 |
| **Threat Feed** | IP matches TOR exit / malicious range | C2 T1090.003 |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/RohitKumarReddySakam/netpulse.git
cd netpulse

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run
python app.py
# → http://localhost:5005
```

### 🐳 Docker

```bash
git clone https://github.com/RohitKumarReddySakam/netpulse.git
cd netpulse
docker build -t netpulse .
docker run -p 5005:5005 netpulse
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔌 API Reference

```bash
# Ingest a network flow
POST /api/flow
{
  "src_ip": "192.168.1.10", "dst_ip": "185.220.101.45",
  "src_port": 54321, "dst_port": 443, "protocol": "TCP",
  "bytes_sent": 1024, "bytes_recv": 512, "packets": 10
}

# Flows (with filters)
GET /api/flows?src_ip=192.168.1.10&protocol=TCP

# Alerts
GET /api/alerts

# Update alert
PATCH /api/alert/<id>
{"status": "closed"}

# Traffic statistics
GET /api/stats

# Host inventory
GET /api/hosts
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 📁 Project Structure

```
netpulse/
├── app.py                  # Flask application & REST API
├── wsgi.py                 # Gunicorn entry point
├── config.py
├── requirements.txt
├── Dockerfile
│
├── core/
│   ├── flow_analyzer.py    # 6 behavioral anomaly detectors
│   ├── threat_feeds.py     # Local TOR + malicious IP lists
│   └── traffic_stats.py    # Aggregate traffic statistics
│
├── templates/
│   ├── index.html          # Network dashboard
│   ├── flows.html          # Flow records table
│   └── alerts.html         # Alert management
│
├── static/                 # CSS + JavaScript
└── tests/                  # 15 pytest tests
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 👨‍💻 Author

<div align="center">

**Rohit Kumar Reddy Sakam**

*DevSecOps Engineer & Security Researcher*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rohit_Kumar_Reddy_Sakam-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/rohitkumarreddysakam)
[![GitHub](https://img.shields.io/badge/GitHub-RohitKumarReddySakam-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/RohitKumarReddySakam)
[![Portfolio](https://img.shields.io/badge/Portfolio-srkrcyber.com-64FFDA?style=for-the-badge&logo=safari&logoColor=black)](https://srkrcyber.com)

> *"Network flows don't lie — beaconing patterns, port scans, and TOR traffic have clear signatures. Built to catch what endpoint agents miss."*

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<div align="center">

**⭐ Star this repo if it helped you!**

[![Star](https://img.shields.io/github/stars/RohitKumarReddySakam/netpulse?style=social)](https://github.com/RohitKumarReddySakam/netpulse)

MIT License © 2025 Rohit Kumar Reddy Sakam

</div>
