"""
online/capture.py — XTI-SOC Phase 1

PacketCaptureEngine: starts/stops/pauses Scapy packet sniffing on a given
network interface and feeds parsed packets into session_store.

Design rules:
  - The sniff callback (_on_packet) MUST return in microseconds.
    No I/O, no locking beyond what session_store.process_packet() does,
    no sleeping, no printing.
  - stop_filter is used so Scapy's sniff() exits cleanly when stop() is called.
  - The capture thread is daemon=True so it dies with the process.
  - Pause silently drops packets (sets paused_flag) — the sniff loop itself
    keeps running; this avoids the latency of restarting it.
  - The timeout background thread inside session_store starts at import time
    (not here). This file does not touch that thread.
"""

import threading
from scapy.all import sniff

from online import parser, session_store


class PacketCaptureEngine:
    """
    Manages a background Scapy sniff thread for one network interface.

    Usage
    -----
    engine = PacketCaptureEngine()
    engine.start(interface="\\Device\\NPF_{GUID}")   # Windows NPF name
    ...
    engine.pause()
    engine.resume()
    engine.stop()
    """

    def __init__(self) -> None:
        self._stop_flag   = threading.Event()
        self._paused_flag = threading.Event()
        self._thread: threading.Thread | None = None
        self._interface: str = ""
        self._bpf_filter: str = ""

        # Packet counter — read by main.py stats printer
        self._packet_count: int = 0
        self._count_lock = threading.Lock()

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self, interface: str, bpf_filter: str = "") -> None:
        """
        Start capturing on the given interface.

        Parameters
        ----------
        interface  : Scapy interface name (NPF GUID on Windows, eth0 on Linux)
        bpf_filter : Optional BPF filter string, e.g. "tcp or udp"
        """
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("Capture already running. Call stop() first.")

        self._interface  = interface
        self._bpf_filter = bpf_filter
        self._stop_flag.clear()
        self._paused_flag.clear()

        self._thread = threading.Thread(
            target=self._capture_loop,
            name="packet-capture",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the capture thread to stop. Returns immediately."""
        self._stop_flag.set()
        # Thread is daemon — it will die on its own once sniff() exits

    def pause(self) -> None:
        """Silently drop all incoming packets until resume() is called."""
        self._paused_flag.set()

    def resume(self) -> None:
        """Resume processing packets after a pause()."""
        self._paused_flag.clear()

    @property
    def is_running(self) -> bool:
        """True if the capture thread is alive (not stopped)."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def is_paused(self) -> bool:
        """True if capture is paused (packets being silently dropped)."""
        return self._paused_flag.is_set()

    def packet_count(self) -> int:
        """Total packets seen since start() (including dropped ones)."""
        with self._count_lock:
            return self._packet_count

    # ── Internal ────────────────────────────────────────────────────────────────

    def _on_packet(self, pkt) -> None:
        """
        Scapy sniff callback — called in the capture thread for every packet.

        MUST return in microseconds:
          - No I/O
          - No blocking
          - No sleeping
          - No printing

        Steps:
          1. Increment counter (tiny lock, very fast)
          2. If paused or stopped, discard immediately
          3. Parse packet → pkt_dict or None
          4. If valid, hand off to session_store.process_packet()
        """
        with self._count_lock:
            self._packet_count += 1

        # Discard if paused or stopped
        if self._paused_flag.is_set() or self._stop_flag.is_set():
            return

        pkt_dict = parser.parse_packet(pkt)
        if pkt_dict is not None:
            session_store.process_packet(pkt_dict)

    def _stop_filter(self, pkt) -> bool:
        """
        Scapy stop_filter: returns True to stop sniffing.
        Called by Scapy after each packet — if True, sniff() exits.
        """
        return self._stop_flag.is_set()

    def _capture_loop(self) -> None:
        """
        Runs in the daemon capture thread.
        Calls Scapy sniff() with store=False (never accumulates packets in RAM).
        """
        sniff(
            iface=self._interface,
            filter=self._bpf_filter,
            prn=self._on_packet,
            stop_filter=self._stop_filter,
            store=False,          # critical — never hold packets in memory
        )
