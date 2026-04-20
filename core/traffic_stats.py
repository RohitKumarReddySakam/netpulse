"""Traffic statistics and baseline building for NETPULSE."""
import logging
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


def compute_stats(flows: list) -> dict:
    """Compute aggregate traffic statistics from a list of flow records."""
    if not flows:
        return {
            "total_flows": 0, "total_bytes": 0, "total_packets": 0,
            "top_talkers": [], "top_destinations": [], "protocol_dist": {},
            "port_dist": {},
        }

    total_bytes = sum(f.get("bytes_sent", 0) + f.get("bytes_recv", 0) for f in flows)
    total_packets = sum(f.get("packets", 0) for f in flows)

    src_bytes = defaultdict(int)
    dst_bytes = defaultdict(int)
    protocols = Counter()
    ports = Counter()

    for f in flows:
        src = f.get("src_ip", "unknown")
        dst = f.get("dst_ip", "unknown")
        b = f.get("bytes_sent", 0)
        src_bytes[src] += b
        dst_bytes[dst] += b
        protocols[f.get("protocol", "unknown")] += 1
        p = f.get("dst_port")
        if p:
            ports[p] += 1

    top_talkers = sorted(src_bytes.items(), key=lambda x: -x[1])[:10]
    top_destinations = sorted(dst_bytes.items(), key=lambda x: -x[1])[:10]
    top_ports = ports.most_common(10)

    return {
        "total_flows": len(flows),
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "total_bytes_mb": round(total_bytes / 1_000_000, 2),
        "top_talkers": [{"ip": ip, "bytes": b, "bytes_mb": round(b/1e6, 2)} for ip, b in top_talkers],
        "top_destinations": [{"ip": ip, "bytes": b, "bytes_mb": round(b/1e6, 2)} for ip, b in top_destinations],
        "protocol_dist": dict(protocols.most_common(10)),
        "port_dist": {str(p): c for p, c in top_ports},
    }
