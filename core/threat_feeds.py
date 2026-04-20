"""
Local threat feed checking — identifies known malicious IPs and domains.
Uses local lists only; no external API calls required.
"""
import ipaddress
import logging

logger = logging.getLogger(__name__)

# Known Tor exit node ranges (representative sample for demonstration)
TOR_RANGES = [
    "185.220.101.0/24", "185.220.102.0/24", "185.220.103.0/24",
    "185.220.0.0/16", "45.142.212.0/24", "162.247.72.0/22",
]

# Known C2/malware ranges (representative — replace with real threat intel feeds)
MALICIOUS_RANGES = [
    "5.188.206.0/24", "91.219.28.0/22", "194.165.16.0/22",
    "45.142.120.0/22", "91.108.4.0/22",
]

# Known malicious/suspicious domains (representative examples)
MALICIOUS_DOMAINS = {
    "evil-domain.tk", "malware.cf", "phishing.ga", "c2server.ml",
    "command-control.info", "botnet-c2.xyz", "ransom-pay.onion",
}

_tor_networks = None
_malicious_networks = None


def _load_networks():
    global _tor_networks, _malicious_networks
    if _tor_networks is None:
        _tor_networks = []
        for cidr in TOR_RANGES:
            try:
                _tor_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
    if _malicious_networks is None:
        _malicious_networks = []
        for cidr in MALICIOUS_RANGES:
            try:
                _malicious_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass


def check_ip(ip: str) -> dict:
    """
    Check an IP against local threat feeds.
    Returns: {"malicious": bool, "tor": bool, "reason": str}
    """
    _load_networks()
    result = {"malicious": False, "tor": False, "reason": "", "ip": ip}

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return result

    # Skip private/loopback
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return result

    for net in _tor_networks:
        if addr in net:
            result["tor"] = True
            result["reason"] = f"IP {ip} is in known Tor exit node range {net}"
            break

    for net in _malicious_networks:
        if addr in net:
            result["malicious"] = True
            result["reason"] = f"IP {ip} is in known malicious range {net}"
            break

    return result


def check_domain(domain: str) -> dict:
    """Check a domain against local threat feeds."""
    domain = domain.lower().strip(".")
    is_malicious = domain in MALICIOUS_DOMAINS or any(
        domain.endswith("." + d) for d in MALICIOUS_DOMAINS
    )
    return {
        "domain": domain,
        "malicious": is_malicious,
        "reason": f"Domain {domain} in local threat feed" if is_malicious else "",
    }
