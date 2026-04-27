"""
online/arp_monitor.py — XTI-SOC

Dedicated Layer 2 monitoring thread using Scapy to track ARP packets.
NFStream ignores ARP, so this fills the Layer 2 blind spot.
Detects:
- ARP Spoofing (IP address moves to a different MAC)
"""

import threading
import time
import uuid
from scapy.all import AsyncSniffer, ARP

class ARPMonitor:
    def __init__(self, alert_queue, interface=None):
        self._alert_queue = alert_queue
        self._interface = interface
        self._stop_flag = threading.Event()
        self._sniffer = None
        
        # IP -> MAC mapping to detect spoofing
        self._ip_mac_table = {}

    def start(self):
        if self._sniffer and self._sniffer.running:
            return
            
        self._stop_flag.clear()
        kwargs = {"filter": "arp", "prn": self._arp_callback, "store": False}
        if self._interface:
            kwargs["iface"] = self._interface
            
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()
        print(f"[ARP MONITOR] Started on Layer 2.")

    def stop(self):
        self._stop_flag.set()
        if self._sniffer:
            self._sniffer.stop()
        
    def _arp_callback(self, pkt):
        if self._stop_flag.is_set():
            return

        if ARP in pkt:
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc

            # We ignore 0.0.0.0
            if src_ip == "0.0.0.0":
                return

            if src_ip in self._ip_mac_table:
                old_mac = self._ip_mac_table[src_ip]
                if old_mac != src_mac:
                    # MAC moved! This is an ARP Spoofing anomaly.
                    self._emit_alert(src_ip, old_mac, src_mac)
                    # Update table to prevent alert storm
                    self._ip_mac_table[src_ip] = src_mac
            else:
                self._ip_mac_table[src_ip] = src_mac

    def _emit_alert(self, ip, old_mac, new_mac):
        print(f"[ARP ANOMALY] {ip} moved from {old_mac} to {new_mac}")
        alert = {
            "src_ip": ip,
            "dst_ip": "255.255.255.255",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "ARP",
            "timestamp": time.time(),
            "duration_s": 0.0,
            "ml_class": "MALICIOUS",
            "attack_type": "ARP Spoofing",
            "ml_probability": 1.0,
            "shap_explanation": [
                {"feature": f"MAC Address Flipped ({old_mac} -> {new_mac})", "shap_value": 0.95},
                {"feature": "ARP Poisoning / Man-in-the-Middle signature match", "shap_value": 0.85}
            ],
            "close_reason": "scapy-arp",
            "fwd_packets": 1,
            "bwd_packets": 0,
            "total_bytes": 42,
            "cti_data": {
                "alert_type": "ARP_ANOMALY",
                "abuse_score": 0,
                "country": "LOCAL",
                "cti_status": "done"
            },
            "alert_id": str(uuid.uuid4()),
            "risk_score": 85.0
        }
        self._alert_queue.put(alert)
