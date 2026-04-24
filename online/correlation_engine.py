"""
online/correlation_engine.py — XTI-SOC

Implements Per-Source Temporal Correlation (Upgrade 2) and DNS Anomaly Detection (Upgrade 4).
Maintains a 60-second rolling window of flows per src_ip.
Detects cross-flow patterns like Port Scans, Brute Force, Volumetric Floods, and DNS flooding.
"""

import threading
import time
import uuid
from collections import defaultdict, deque

class CorrelationEngine:
    def __init__(self, alert_queue):
        self._alert_queue = alert_queue
        # src_ip -> deque of (timestamp, flow_summary)
        self._src_ip_window = defaultdict(deque)
        self._lock = threading.Lock()
        
        # Track when we last alerted an IP for a specific anomaly to avoid spam
        # ip -> {anomaly_type: last_alert_time}
        self._last_alert_time = defaultdict(dict)
        self._last_analyzed = {}
        self._cooldown_s = 60.0

    def add_flow(self, flow):
        """
        Takes an nfstream flow object and adds it to the rolling window.
        Returns None. Alerts are pushed to the alert_queue directly.
        """
        now = time.time()
        
        # DNS Protocol check (nDPI string)
        protocol = str(flow.protocol).upper()
        
        flow_summary = {
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "protocol": protocol,
            "requested_server_name": getattr(flow, "requested_server_name", ""),
            "duration_s": flow.bidirectional_duration_ms / 1000.0,
            "bytes": flow.bidirectional_bytes
        }

        with self._lock:
            window = self._src_ip_window[flow.src_ip]
            window.append((now, flow_summary))
            
            # Cap the window size to prevent memory exhaustion during DoS attacks
            if len(window) > 2000:
                window.popleft()

            # Throttle analysis to once per second per IP to prevent CPU lag
            last_analyzed = self._last_analyzed.get(flow.src_ip, 0)
            if now - last_analyzed > 1.0:
                self._purge_old_entries(flow.src_ip, now)
                self._analyze(flow.src_ip, now)
                self._last_analyzed[flow.src_ip] = now

    def _purge_old_entries(self, src_ip, now):
        window = self._src_ip_window[src_ip]
        while window and window[0][0] < now - 60.0:
            window.popleft()
        if not window:
            del self._src_ip_window[src_ip]

    def _analyze(self, src_ip, now):
        window = self._src_ip_window.get(src_ip, [])
        if not window:
            return

        flow_count = len(window)
        distinct_dst_ports = set(f["dst_port"] for _, f in window)
        flows_to_22_21 = sum(1 for _, f in window if f["dst_port"] in (22, 21))
        dns_queries = sum(1 for _, f in window if "DNS" in f["protocol"] or f["dst_port"] == 53)

        # 1. Port Scan (>50 distinct dst_ports in 60s)
        if len(distinct_dst_ports) > 50:
            self._trigger_alert(src_ip, now, "Port Scan", 80.0)

        # 2. SSH/FTP Brute Force (>100 flows to port 22/21 in 60s)
        if flows_to_22_21 > 100:
            self._trigger_alert(src_ip, now, "SSH/FTP Brute Force", 85.0)

        # 3. Volumetric Flood (>1000 flows in 60s)
        if flow_count > 1000:
            self._trigger_alert(src_ip, now, "Volumetric Flood", 90.0)

        # 4. DNS Anomaly (>100 DNS queries in 60s)
        if dns_queries > 100:
            self._trigger_alert(src_ip, now, "DNS Flooding", 75.0)

    def _trigger_alert(self, src_ip, now, attack_type, risk_score):
        last_time = self._last_alert_time[src_ip].get(attack_type, 0)
        if now - last_time < self._cooldown_s:
            return  # Cooldown active
            
        self._last_alert_time[src_ip][attack_type] = now
        
        print(f"[CORRELATION] {src_ip} flagged for {attack_type}")

        alert = {
            "src_ip": src_ip,
            "dst_ip": "MULTIPLE",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "CORRELATED",
            "timestamp": now,
            "duration_s": 60.0,
            "ml_class": "MALICIOUS",
            "attack_type": attack_type,
            "ml_probability": 1.0,
            "shap_explanation": None,
            "close_reason": "correlation_engine",
            "fwd_packets": 0,
            "bwd_packets": 0,
            "total_bytes": 0,
            "cti_data": {
                "alert_type": "CORRELATION",
                "abuse_score": 0,
                "country": "LOCAL",
                "cti_status": "done"
            },
            "alert_id": str(uuid.uuid4()),
            "risk_score": risk_score
        }
        self._alert_queue.put(alert)
