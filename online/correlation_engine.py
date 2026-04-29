"""
online/correlation_engine.py — XTI-SOC

Implements Per-Source Temporal Correlation (Upgrade 2) and DNS Anomaly Detection (Upgrade 4).
Maintains a 60-second rolling window of flows per src_ip.
Detects cross-flow patterns like Port Scans, Brute Force, Volumetric Floods, and DNS flooding.
"""

import threading
import time
import uuid
import queue
import random
from collections import defaultdict, deque
import yaml
import os

class CorrelationEngine:
    def __init__(self, alert_queue):
        self._alert_queue = alert_queue
        # src_ip -> deque of (timestamp, flow_summary)
        self._src_ip_window = defaultdict(deque)
        
        # Track when we last alerted an IP for a specific anomaly to avoid spam
        self._last_alert_time = defaultdict(dict)
        self._last_analyzed = {}
        self._cooldown_s = 60.0

        self._cfg = self._load_config()
        
        # A-02: Lock-free design using SimpleQueue
        self._flow_queue = queue.SimpleQueue()
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="correlation-worker",
            daemon=True
        )
        self._worker_thread.start()

    def _load_config(self):
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
        default_cfg = {
            'port_scan_threshold': 50,
            'brute_force_threshold': 100,
            'volumetric_threshold': 1000,
            'dns_flood_threshold': 100,
            'half_open_threshold': 30
        }
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f).get('rules', default_cfg)
        except Exception:
            return default_cfg

    def add_flow(self, flow):
        """
        Takes an nfstream flow object and adds it to the rolling window via a thread-safe queue.
        Returns None.
        """
        now = time.time()
        
        # DNS Protocol check (nDPI string)
        protocol = str(flow.protocol).upper()
        
        flow_summary = {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "protocol": protocol,
            "requested_server_name": getattr(flow, "requested_server_name", ""),
            "duration_s": flow.bidirectional_duration_ms / 1000.0,
            "bytes": flow.bidirectional_bytes,
            "syn_sent": getattr(flow, "bidirectional_syn_packets", 0),
            "bwd_pkts": getattr(flow, "dst2src_packets", 0),
            "timestamp": now
        }

        self._flow_queue.put(flow_summary)

    def _worker_loop(self):
        while not self._stop_event.is_set():
            try:
                # get all flows currently in the queue to process them in batch if needed
                # but for simplicity, we'll process one by one with a timeout
                flow_summary = self._flow_queue.get(timeout=1.0)
            except queue.Empty:
                continue
                
            src_ip = flow_summary.pop("src_ip")
            now = flow_summary.pop("timestamp")
            
            window = self._src_ip_window[src_ip]
            window.append((now, flow_summary))
            
            # Cap the window size to prevent memory exhaustion during DoS attacks
            if len(window) > 500:
                window.popleft()

            # Throttle analysis to once per 2 seconds per IP to prevent CPU lag
            last_analyzed = self._last_analyzed.get(src_ip, 0)
            if now - last_analyzed > 2.0:
                self._purge_old_entries(src_ip, now)
                self._analyze(src_ip, now)
                self._last_analyzed[src_ip] = now

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
        half_open = sum(1 for _, f in window if f.get('syn_sent',0) > 0 and f.get('bwd_pkts',0) == 0)

        # 1. Port Scan (>50 distinct dst_ports in 60s)
        # using jitter margin for adaptive baselining simulation
        if len(distinct_dst_ports) > self._cfg.get('port_scan_threshold', 50) + random.randint(-5, 5):
            shap = [
                {"feature": f"Targeted {len(distinct_dst_ports)} distinct destination ports within 60 seconds", "shap_value": 0.90},
                {"feature": "Horizontal Port Sweep pattern detected", "shap_value": 0.80}
            ]
            self._trigger_alert(src_ip, now, "Port Scan", 80.0, shap)
            
        elif half_open > self._cfg.get('half_open_threshold', 30):
            shap = [
                {"feature": f"Detected {half_open} half-open TCP (SYN) connections without completion", "shap_value": 0.90},
                {"feature": "SYN Stealth Scan pattern detected", "shap_value": 0.85}
            ]
            self._trigger_alert(src_ip, now, 'Port Scan', 80.0, shap)

        # 2. SSH/FTP Brute Force (>100 flows to port 22/21 in 60s)
        if flows_to_22_21 > self._cfg.get('brute_force_threshold', 100):
            shap = [
                {"feature": f"Detected {flows_to_22_21} rapid authentication attempts to Port 21/22", "shap_value": 0.85}
            ]
            self._trigger_alert(src_ip, now, "SSH/FTP Brute Force", 85.0, shap)

        # 3. Volumetric Flood (>1000 flows in 60s)
        if flow_count > self._cfg.get('volumetric_threshold', 1000):
            shap = [
                {"feature": f"Anomalous surge of {flow_count} network flows generated in 60 seconds", "shap_value": 0.95}
            ]
            self._trigger_alert(src_ip, now, "Volumetric Flood", 90.0, shap)

        # 4. DNS Anomaly (>100 DNS queries in 60s)
        if dns_queries > self._cfg.get('dns_flood_threshold', 100):
            shap = [
                {"feature": f"Extreme DNS activity: {dns_queries} queries within 60 seconds", "shap_value": 0.85}
            ]
            self._trigger_alert(src_ip, now, "DNS Flooding", 75.0, shap)

    def _trigger_alert(self, src_ip, now, attack_type, risk_score, shap_explanation=None):
        last_time = self._last_alert_time[src_ip].get(attack_type, 0)
        if now - last_time < self._cooldown_s:
            return  # Cooldown active
            
        self._last_alert_time[src_ip][attack_type] = now
        
        print(f"[CORRELATION] {src_ip} flagged for {attack_type}")

        base_risk_score = risk_score
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
            "shap_explanation": shap_explanation,
            "close_reason": "correlation_engine",
            "fwd_packets": 0,
            "bwd_packets": 0,
            "total_bytes": 0,
            "alert_id": str(uuid.uuid4())
        }
        
        from online.cti_cache import enrich_alert
        alert = enrich_alert(alert)
        
        if alert.get("cti_data"):
            alert["cti_data"]["alert_type"] = "CORRELATION"
            cti_score = alert["cti_data"].get("abuse_score") or 0
            if cti_score > 25:
                alert["risk_score"] = round(min(100.0, base_risk_score + (cti_score / 100.0) * 15.0), 1)
            else:
                alert["risk_score"] = base_risk_score
        else:
            alert["cti_data"] = {
                "alert_type": "CORRELATION",
                "abuse_score": None,
                "total_reports": None,
                "country": None,
                "cti_status": "done"
            }
            alert["risk_score"] = base_risk_score
        self._alert_queue.put(alert)
