"""
tools/attack_simulator.py

Generates real attack traffic on loopback (127.0.0.1).
nfstream captures these flows and your ML pipeline classifies them.

No external machine needed. Runs entirely on your PC.
"""

import socket
import time
import threading
import sys


TARGET = "127.0.0.1"


# ── Attack functions ───────────────────────────────────────────────────────────

def syn_flood(count: int = 3000, rate_per_sec: int = 500):
    """
    Rapid TCP connection attempts without completing handshake.
    Pattern: high SYN count, low bwd packets, high Flow Pkts/s
    Matches: DDoS-LOIC-HTTP, DoS-Hulk in CICIDS2018
    """
    print(f"\n[SYN FLOOD] {TARGET}:80 | {count} packets | "
          f"{rate_per_sec} pkt/s")

    interval = 1.0 / rate_per_sec
    sent = 0

    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            s.connect_ex((TARGET, 80))
            # Do NOT complete handshake — close immediately
            s.close()
            sent += 1
            if sent % 500 == 0:
                print(f"  [{sent}/{count}] SYN packets sent")
            time.sleep(interval)
        except Exception:
            pass

    print(f"[SYN FLOOD] Done — {sent} sent")


def udp_flood(count: int = 5000, payload_size: int = 64):
    """
    High volume UDP packets.
    Pattern: high packet rate, no ACK/SYN flags, one-directional
    Matches: DDoS-LOIC-UDP in CICIDS2018
    """
    print(f"\n[UDP FLOOD] {TARGET}:53 | {count} packets | "
          f"{payload_size}B each")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'A' * payload_size
    sent = 0

    try:
        for i in range(count):
            sock.sendto(payload, (TARGET, 53))
            sent += 1
            if sent % 1000 == 0:
                print(f"  [{sent}/{count}] UDP packets sent")
            time.sleep(0.0002)  # 5000 pkt/s
    finally:
        sock.close()

    print(f"[UDP FLOOD] Done — {sent} sent")


def port_scan(start: int = 1, end: int = 1000):
    """
    Sequential port scanning.
    Pattern: many RST responses, sequential ports, short flows
    Matches: PortScan in CICIDS2018
    """
    print(f"\n[PORT SCAN] {TARGET} | ports {start}-{end}")

    open_ports = []
    scanned = 0

    for port in range(start, end + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.02)
            result = s.connect_ex((TARGET, port))
            if result == 0:
                open_ports.append(port)
            s.close()
            scanned += 1
        except Exception:
            pass

    print(f"[PORT SCAN] Done — {scanned} ports scanned | "
          f"Open: {open_ports}")


def http_flood(count: int = 500):
    """
    Rapid HTTP GET requests.
    Pattern: high PSH count, port 80, many short TCP flows
    Matches: DoS-Hulk, DDoS-LOIC-HTTP in CICIDS2018

    Note: needs a listening server on port 80.
    If nothing is listening, connection refused → still generates
    TCP RST flows that nfstream captures.
    """
    print(f"\n[HTTP FLOOD] {TARGET}:80 | {count} requests")

    request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Accept: */*\r\n"
        b"Connection: close\r\n\r\n"
    )

    sent = 0
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((TARGET, 80))
            s.send(request)
            s.close()
            sent += 1
        except Exception:
            pass
        time.sleep(0.002)

    print(f"[HTTP FLOOD] Done — {sent} requests")


def slow_http_test(count: int = 50, hold_seconds: int = 30):
    """
    Slowloris-style attack — open many connections and hold them.
    Pattern: many long-duration flows, low bytes, high connection count
    Matches: DoS-Slowloris in CICIDS2018
    """
    print(f"\n[SLOWLORIS] {TARGET}:80 | {count} connections | "
          f"hold {hold_seconds}s")

    sockets = []
    partial_request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
    )
    # Deliberately incomplete — no final \r\n

    # Open connections
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect((TARGET, 80))
            s.send(partial_request)
            sockets.append(s)
        except Exception:
            pass

    print(f"  Opened {len(sockets)} connections, holding for {hold_seconds}s...")

    # Send keep-alive headers periodically
    end_time = time.time() + hold_seconds
    while time.time() < end_time:
        for s in sockets[:]:
            try:
                s.send(b"X-Keep-Alive: yes\r\n")
            except Exception:
                sockets.remove(s)
        time.sleep(5)

    # Close all
    for s in sockets:
        try: s.close()
        except: pass

    print(f"[SLOWLORIS] Done")


# ── Simple HTTP server for realistic attacks ───────────────────────────────────

def _start_http_server(port: int = 80):
    """Start a minimal HTTP server so HTTP flood gets real responses."""
    import http.server
    import threading

    class QuietHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, format, *args):
            pass  # suppress output

    try:
        server = http.server.HTTPServer(("127.0.0.1", port), QuietHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        print(f"[SERVER] HTTP server started on port {port}")
        return server
    except OSError:
        print(f"[SERVER] Port {port} in use — HTTP flood will use RST flows")
        return None


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("XTI-SOC Attack Simulator (Loopback)")
    print(f"Target: {TARGET}")
    print("=" * 60)
    print()
    print("Make sure online.main is running on loopback interface first.")
    print("Select interface [7] Software Loopback Interface 1 (127.0.0.1)")
    print()
    print("Select attack:")
    print("  [1] SYN Flood      — high SYN count, no bwd packets")
    print("  [2] UDP Flood      — high packet rate, no flags")
    print("  [3] Port Scan      — many RST responses, sequential ports")
    print("  [4] HTTP Flood     — high PSH, port 80 (starts local server)")
    print("  [5] Slowloris      — many long connections, low bytes")
    print("  [6] Full sequence  — all attacks, best for demo")

    choice = input("\nChoice [1-6]: ").strip()

    if choice == "1":
        syn_flood(count=3000, rate_per_sec=500)

    elif choice == "2":
        udp_flood(count=5000, payload_size=64)

    elif choice == "3":
        port_scan(start=1, end=1000)

    elif choice == "4":
        _start_http_server(80)
        time.sleep(1)
        http_flood(count=500)

    elif choice == "5":
        _start_http_server(80)
        time.sleep(1)
        slow_http_test(count=50, hold_seconds=30)

    elif choice == "6":
        print("\nFull attack sequence — watch your pipeline terminal\n")

        # Start HTTP server for realistic flows
        _start_http_server(80)
        time.sleep(1)

        attacks = [
            ("SYN Flood (DoS pattern)",
             lambda: syn_flood(3000, 500)),

            ("UDP Flood (DDoS-LOIC-UDP pattern)",
             lambda: udp_flood(5000, 64)),

            ("Port Scan (PortScan pattern)",
             lambda: port_scan(1, 500)),

            ("HTTP Flood (DoS-Hulk pattern)",
             lambda: http_flood(300)),
        ]

        for name, fn in attacks:
            print(f"\n{'─'*50}")
            print(f"ATTACK: {name}")
            print(f"{'─'*50}")
            fn()
            print(f"\nWaiting 10s — check your pipeline for MALICIOUS alerts...")
            time.sleep(10)

        print("\n[DONE] Full sequence complete.")
        print("Check your pipeline terminal for MALICIOUS alerts.")

    else:
        print("Invalid choice")
        sys.exit(1)


if __name__ == "__main__":
    main()