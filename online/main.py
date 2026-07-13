"""
online/main.py — XTI-SOC

Entry point for the online pipeline.
Uses nfstream for capture + feature extraction.
Launches FastAPI + WebSocket server and the capture engine.
"""

import sys
import threading
import time
import uvicorn
from dotenv import load_dotenv

load_dotenv()

from online.interfaces import get_interfaces, get_default_interface
from online.nfstream_engine import NFStreamEngine
from online.arp_monitor import ARPMonitor
from online.alert_queue import alert_queue

def _pick_interface() -> str:
    """
    List available interfaces and let user pick one.
    nfstream accepts the same interface names as Scapy/Wireshark.
    """
    ifaces = get_interfaces()
    if not ifaces:
        print("[ERROR] No network interfaces found. Run as Administrator.")
        sys.exit(1)

    default_name = get_default_interface()

    print("\nAvailable network interfaces:")
    print("-" * 60)
    for i, iface in enumerate(ifaces):
        marker = " — default" if iface["name"] == default_name else ""
        print(f"  [{i}] {iface['display']}{marker}")
    print("-" * 60)

    raw = input(
        f"Select interface [0-{len(ifaces)-1}] (Enter = default): "
    ).strip()

    if raw == "":
        return default_name

    try:
        idx = int(raw)
        return ifaces[idx]["name"]
    except (ValueError, IndexError):
        print("[ERROR] Invalid selection.")
        sys.exit(1)

def main() -> None:
    iface = _pick_interface()

    engine = NFStreamEngine(output_queue=alert_queue)
    engine.start(interface=iface)

    arp_monitor = ARPMonitor(alert_queue=alert_queue, interface=iface)
    arp_monitor.start()

    print(f"\n✅ Capture started on {iface}")
    print("🔌 API server: http://localhost:8000")
    print("📊 Dashboard:  http://localhost:3000")
    print("   Run 'cd dashboard && npm run dev' in another terminal\n")
    
    from api.server import app
    try:
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
    finally:
        print("\n[MAIN] Shutting down capture threads...")
        engine.stop()
        arp_monitor.stop()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nShutting down...")