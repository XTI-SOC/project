"""
online/parser.py — XTI-SOC Phase 1

Parse a raw Scapy packet into a structured dict for session_store.py.
Returns None for non-IP or malformed packets.

tcp_flags is ALWAYS a Python set[str] such as {"FIN", "ACK"}.
It is NEVER a string or int. session_store.py checks: if "FIN" in pkt["tcp_flags"].
"""

import time
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Bit-mask → flag name mapping for TCP
_TCP_FLAG_BITS: list[tuple[int, str]] = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
]


def _parse_tcp_flags(flags_int: int) -> set:
    """
    Convert Scapy's TCP flags integer into a Python set of flag-name strings.

    Returns a set[str], e.g. {"SYN", "ACK"}.
    The caller always does:  if "FIN" in pkt["tcp_flags"]
    NEVER convert this to a string — that brings back the substring bug.
    """
    result: set[str] = set()
    for bit, name in _TCP_FLAG_BITS:
        if flags_int & bit:
            result.add(name)
    return result


def parse_packet(pkt) -> dict | None:
    """
    Parse a raw Scapy packet into a structured dict.

    Returns None if the packet:
      - Is not an IP packet (ARP, non-IP, etc.)
      - Is malformed / missing expected layers

    Returned dict fields
    --------------------
    src_ip    : str
    dst_ip    : str
    src_port  : int | None   (None for ICMP/OTHER)
    dst_port  : int | None
    protocol  : str          "TCP" | "UDP" | "ICMP" | "OTHER"
    pkt_size  : int          len(pkt) in bytes
    tcp_flags : set[str]     e.g. {"SYN", "ACK"} — empty set if not TCP
    timestamp : float        time.time() at parse time
    """
    try:
        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        ts = time.time()

        src_ip: str = ip.src
        dst_ip: str = ip.dst
        src_port: int | None = None
        dst_port: int | None = None
        protocol: str = "OTHER"
        tcp_flags: set[str] = set()  # always a set — never a string

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            protocol = "TCP"
            # _parse_tcp_flags always returns a set[str]
            tcp_flags = _parse_tcp_flags(int(tcp.flags))

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            protocol = "UDP"

        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
            # ICMP has no ports — src_port and dst_port remain None

        return {
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  protocol,
            "pkt_size":  len(pkt),
            "tcp_flags": tcp_flags,   # set[str] — always
            "timestamp": ts,
        }

    except Exception:
        # Malformed packet — discard silently
        return None
