"""
tools/attack_simulator.py

Generates real attack traffic on loopback (127.0.0.1).
nfstream captures these flows and your ML pipeline classifies them.

Modified to bypass NFStream Quality Filters (>= 4 pkts, >= 10ms duration).
"""

import socket
import time
import threading
import sys


TARGET = "127.0.0.1"


# ── Simple HTTP/Dummy server for realistic attacks ─────────────────────────────

def _start_http_server(port: int = 8080):
    """Start a minimal HTTP server so HTTP flood gets real responses."""
    import http.server
    
    class QuietHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        def log_message(self, format, *args): pass

    try:
        server = http.server.HTTPServer((TARGET, port), QuietHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        print(f"[SERVER] HTTP server started on port {port}")
        return server
    except OSError:
        pass
    return None

def _start_dummy_listeners(ports: list[int]):
    """Starts basic TCP listeners so port scans pass the 4-packet filter."""
    def listener(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((TARGET, p))
            s.listen(5)
            while True:
                conn, addr = s.accept()
                time.sleep(0.01) # Hold for filter duration
                conn.send(b"X")
                conn.close()
        except OSError:
            pass
            
    for p in ports:
        threading.Thread(target=listener, args=(p,), daemon=True).start()
    print(f"[SERVER] Dummy listeners running on ports {ports}")

# ── Attack functions ───────────────────────────────────────────────────────────

def syn_flood(count: int = 2000, rate_per_sec: int = 150):
    """
    Rapid TCP connection setup and teardown.
    Because we connect to an open port and sleep 15ms, it generates
    ~6-8 packets per flow, passing the NFStream filters and hitting 
    the model as an intense DoS/BruteForce pattern.
    """
    print(f"\n[SYN/TCP FLOOD] {TARGET}:8080 | {count} flows | ~{rate_per_sec} fl/s")
    interval = 1.0 / rate_per_sec
    sent = 0

    def task():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((TARGET, 8080))
            # Sleep 15ms minimum to stretch duration > 10ms for NFStream
            time.sleep(0.015) 
            # Send a trailing byte for extra packets
            s.send(b"X")
            # Force RST instead of full FIN closure
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
            s.close()
        except Exception:
            pass

    for i in range(count):
        threading.Thread(target=task, daemon=True).start()
        sent += 1
        if sent % 500 == 0:
            print(f"  [{sent}/{count}] TCP/SYN flood attempts launched")
        time.sleep(interval)

    print(f"[SYN/TCP FLOOD] Done — wait 10s for NFStream active flows to finalize")


def udp_flood(count: int = 5000, payload_size: int = 64):
    """
    High volume UDP packets, slowed down to span 20 seconds.
    This creates one giant flow that hits NFStream's active_timeout or
    emits exactly 15s after finishing.
    Matches: DDoS-LOIC-UDP
    """
    print(f"\n[UDP FLOOD] {TARGET}:53 | {count} packets | {payload_size}B each")
    print("  Note: NFStream will emit this 15-20 seconds AFTER it starts.")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'A' * payload_size
    sent = 0
    # Send 5000 packets over 20 seconds (1 pkt every 4ms)
    try:
        for i in range(count):
            sock.sendto(payload, (TARGET, 53))
            sent += 1
            if sent % 1000 == 0:
                print(f"  [{sent}/{count}] UDP packets sent")
            time.sleep(0.004) 
    finally:
        sock.close()

    print(f"[UDP FLOOD] Done — check terminal in ~15s")


def port_scan(count_per_port: int = 50):
    """
    Sequential port scanning of our DUMMY open ports.
    If we scan closed ports, they produce 2 packets (RST) and fail the filter.
    Scanning these 5 open dummy ports rapidly satisfies the model's PortScan logic.
    """
    ports = [50000, 50001, 50002, 50003, 50004]
    print(f"\n[PORT SCAN] {TARGET} | Scanning 5 dummy open ports {count_per_port}x each")

    open_ports = []
    scanned = 0

    def task(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((TARGET, p)) == 0:
                time.sleep(0.012) # >10ms filter
                open_ports.append(p)
            s.close()
        except:
            pass

    for iteration in range(count_per_port):
        for port in ports:
            threading.Thread(target=task, args=(port,), daemon=True).start()
            scanned += 1
            time.sleep(0.01)

    print(f"[PORT SCAN] Done — {scanned} scans fired")


def http_flood(count: int = 500):
    """
    Rapid HTTP GET requests to port 8080 (DoS-Hulk).
    Sleeps 10-15ms internally to bypass duration filter.
    """
    print(f"\n[HTTP FLOOD] {TARGET}:8080 | {count} requests")

    request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Accept: */*\r\n"
        b"Connection: close\r\n\r\n"
    )

    sent = 0
    def perform_request():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((TARGET, 8080))
            s.send(request)
            time.sleep(0.012)
            s.recv(1024) # Pull response so it registers Fwd/Bwd bytes
            time.sleep(0.005)
            s.close()
        except Exception:
            pass

    for i in range(count):
        threading.Thread(target=perform_request, daemon=True).start()
        sent += 1
        if sent % 100 == 0:
            print(f"  [{sent}/{count}] requests")
        time.sleep(0.002)

    print(f"[HTTP FLOOD] Done — {sent} requests")


def _botnet():
    """Periodic small payloads on one long TCP connection (Botnet)."""
    print(f"\n[BOTNET] {TARGET}:8080 | Keepalive beaconing for 70s")
    print("  This triggers the 60s active_timeout in NFStream.")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET, 8080))
        for i in range(14):
            s.send(b'KEEPALIVE_BEACON_64B_PAYLOAD_PADDING_BOTNET_C2_COMMS')
            print(f"  [Beacon {i+1}/14] sent")
            time.sleep(5)
        s.close()
        print("[BOTNET] Done")
    except Exception as e:
        print(f"  Error: {e}")

def _infiltration():
    """Large payload burst followed by lateral ping-pongs (Infiltration)."""
    print(f"\n[INFILTRATION] {TARGET}:8080 | Massive drop + Lateral movement")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET, 8080))
        print("  Dropping 2MB payload...")
        s.send(b'X' * 1024 * 1024 * 2) # 2MB
        time.sleep(5)
        print("  Lateral movement commands...")
        for i in range(5):
             s.send(b'dir\r\n')
             time.sleep(1)
        s.close()
        print("[INFILTRATION] Done")
    except Exception as e:
        print(f"  Error: {e}")

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("XTI-SOC Attack Simulator (NFStream Bypass Edition)")
    print(f"Target: {TARGET}")
    print("=" * 60)
    print()
    print("Make sure online.main is running on loopback interface first.")
    print("Select interface [7] Software Loopback Interface 1 (127.0.0.1)")
    print()
    print("Select attack:")
    print("  [1] SYN/TCP Flood  — high flow pkts/s, fast teardown")
    print("  [2] UDP Flood      — massive continuous UDP datagram stream")
    print("  [3] Port Scan      — multi-port hit simulating map tools")
    print("  [4] HTTP Flood     — high PSH, DoS-Hulk simulation")
    print("  [5] Botnet         — periodic C2 beaconing (Takes 70s)")
    print("  [6] Infiltration   — massive data drop + lateral movement")
    print("  [7] Full sequence  — all attacks (Warning: Takes ~3 minutes)")

    # Startup required backing infrastructure
    _start_http_server(8080)
    _start_dummy_listeners([50000, 50001, 50002, 50003, 50004])

    choice = input("\nChoice [1-7]: ").strip()

    if choice == "1":
        syn_flood(count=2000, rate_per_sec=150)
    elif choice == "2":
        udp_flood(count=5000, payload_size=64)
    elif choice == "3":
        port_scan(count_per_port=50)
    elif choice == "4":
        http_flood(count=500)
    elif choice == "5":
        _botnet()
    elif choice == "6":
        _infiltration()
    elif choice == "7":
        print("\nFull attack sequence starting...\n")
        attacks = [
            ("SYN/TCP Flood", lambda: syn_flood(1000, 150)),
            ("UDP Flood", lambda: udp_flood(2000, 64)),
            ("Port Scan", lambda: port_scan(30)),
            ("HTTP Flood", lambda: http_flood(300)),
            ("Infiltration", _infiltration),
        ]
        
        for name, fn in attacks:
            print(f"\n{'─'*50}")
            print(f"ATTACK: {name}")
            print(f"{'─'*50}")
            fn()
            print(f"\nWaiting 15s to guarantee NFStream processes active flows...")
            time.sleep(15)

        print("\n[DONE] Full sequence complete.")
        print("Check your pipeline terminal for MALICIOUS alerts.")
    else:
        print("Invalid choice")
        sys.exit(1)


if __name__ == "__main__":
    main()