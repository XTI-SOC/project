"""
online/main.py — XTI-SOC

Entry point for the online pipeline.
Uses nfstream for capture + feature extraction.
Phase 5 will replace this with FastAPI + WebSocket server.

Run with:
  python -m online.main
"""

import signal
import sys
import threading
import time
import queue

from online.nfstream_engine import NFStreamEngine, get_stats
from online.alert_queue import alert_queue, get_stats as ml_get_stats

# ── Interface selection ────────────────────────────────────────────────────────

def _pick_interface() -> str:
    """
    List available interfaces and let user pick one.
    nfstream accepts the same interface names as Scapy/Wireshark.
    """
    import nfstream

    # nfstream can list interfaces
    try:
        interfaces = nfstream.NFStreamer.__doc__  # fallback
    except Exception:
        pass

    # Use Scapy interface list (already in online/interfaces.py)
    from online.interfaces import get_interfaces, get_default_interface

    ifaces = get_interfaces()
    if not ifaces:
        print("[ERROR] No network interfaces found. Run as Administrator.")
        sys.exit(1)

    default_name = get_default_interface()

    print("\nAvailable network interfaces:")
    print("-" * 60)
    for i, iface in enumerate(ifaces):
        marker = " ◄ default" if iface["name"] == default_name else ""
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


# ── Alert consumer (prints to terminal) ───────────────────────────────────────

def _consumer_loop() -> None:
    """Read alerts from alert_queue and print them."""
    SEP = "═" * 55
    while True:
        try:
            alert = alert_queue.get(timeout=1.0)
            print(f"\n{SEP}")
            print(f"ALERT [{alert['ml_class']}] "
                  f"p={alert['ml_probability']:.3f}")
            print(f"  {alert['src_ip']}:{alert['src_port']} → "
                  f"{alert['dst_ip']}:{alert['dst_port']} "
                  f"({alert['protocol']})")
            print(f"  Duration: {alert['duration_s']:.3f}s  |  "
                  f"Bytes: {alert['total_bytes']:,}")
            print(f"  Fwd pkts: {alert['fwd_packets']}  |  "
                  f"Bwd pkts: {alert['bwd_packets']}")
            print(SEP)
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[CONSUMER ERROR] {e}")


# ── Stats printer ──────────────────────────────────────────────────────────────

def _stats_loop(engine: NFStreamEngine) -> None:
    while True:
        time.sleep(10)
        nf = get_stats()          # from nfstream_engine
        ml = ml_get_stats()       # from alert_queue
        print(
            f"[STATS] Flows: {nf['total_flows']:>6}  |  "
            f"Malicious: {nf['malicious_count']:>4}  |  "
            f"Benign: {nf['benign_count']:>4}  |  "
            f"Filtered: {nf['filtered_microflows']:>4}  |  "
            f"Errors: {nf['skipped_errors']:>3}  |  "
            f"ML errors: {ml['errors']:>3}"
        )


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    iface = _pick_interface()

    engine = NFStreamEngine(output_queue=alert_queue)
    engine.start(interface=iface)

    print(f"\nCapture started on: {iface}")
    print("Waiting for flows to close...")
    print("(Generate traffic or run an attack. Press Ctrl+C to stop.)\n")

    consumer = threading.Thread(
        target=_consumer_loop,
        name="alert-consumer",
        daemon=True,
    )
    consumer.start()

    stats = threading.Thread(
        target=_stats_loop,
        args=(engine,),
        name="stats-printer",
        daemon=True,
    )
    stats.start()

    try:
        if hasattr(signal, "pause"):
            signal.pause()
        else:
            while True:
                time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        print("\n[STOPPING] Shutting down...")
        engine.stop()
        time.sleep(1)
        print("[DONE]")


if __name__ == "__main__":
    main()