import os
import time
import threading
import ipaddress
import requests

_cache: dict = {}
_stats: dict = {
    "cache_hits": 0,
    "api_calls": 0,
    "api_errors": 0,
    "private_skips": 0
}
_lock = threading.Lock()
_key_warned = False
CTI_THRESHOLD = 25

def get_cti_stats() -> dict:
    """Returns the CTI statistics."""
    with _lock:
        return _stats.copy()

def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP is private, loopback, or link-local."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return True  # If it's malformed, treat as private/skip

def enrich_alert(alert: dict) -> dict:
    """
    Enriches the alert dict with CTI data from AbuseIPDB.
    Never raises. All exceptions are caught and return the alert unchanged with cti_data=None.
    """
    global _key_warned
    try:
        src = alert.get("src_ip", "")
        dst = alert.get("dst_ip", "")
        
        src_priv = _is_private_ip(src)
        dst_priv = _is_private_ip(dst)
        
        ml_prob = alert.get("ml_probability", 0.0)
        ml_class = alert.get("ml_class", "BENIGN")

        # Step 1: PRIVATE IP CHECK
        if src_priv and dst_priv:
            with _lock:
                _stats["private_skips"] += 1
            
            risk_score = round(ml_prob * 100, 1) if ml_class == "MALICIOUS" else 0.0
            alert_type = "ML_ONLY" if ml_class == "MALICIOUS" else "NO_ALERT"
            
            alert["cti_data"] = {
                "alert_type": alert_type,
                "risk_score": risk_score,
                "abuse_score": None,
                "country": None,
                "total_reports": None,
                "lookup_ip": None
            }
            alert["risk_score"] = risk_score
            return alert
        
        # Determine lookup IP: prefer dst if public, else src
        lookup_ip = dst if not dst_priv else src

        cti_result = None
        
        # Step 2: CACHE CHECK
        with _lock:
            cached = _cache.get(lookup_ip)
            if cached:
                if time.time() > cached["expires"]:
                    del _cache[lookup_ip]
                else:
                    cti_result = cached
                    _stats["cache_hits"] += 1
            
        # Step 3: API CALL
        if cti_result is None:
            api_key = os.environ.get("ABUSEIPDB_KEY")
            if not api_key:
                with _lock:
                    if not _key_warned:
                        print("[CTI WARNING] ABUSEIPDB_KEY not set. CTI enrichment disabled.")
                        _key_warned = True
                cti_result = None
            else:
                try:
                    url = "https://api.abuseipdb.com/api/v2/check"
                    headers = {"Key": api_key, "Accept": "application/json"}
                    params = {"ipAddress": lookup_ip, "maxAgeInDays": "90"}
                    
                    # 3 second hard timeout
                    resp = requests.get(url, headers=headers, params=params, timeout=3.0)
                    resp.raise_for_status()
                    data = resp.json().get("data", {})
                    
                    cti_result = {
                        "score": data.get("abuseConfidenceScore", 0),
                        "country": data.get("countryCode", ""),
                        "reports": data.get("totalReports", 0)
                    }
                    
                    with _lock:
                        _cache[lookup_ip] = {
                            "score": cti_result["score"],
                            "country": cti_result["country"],
                            "reports": cti_result["reports"],
                            "expires": time.time() + 3600
                        }
                        _stats["api_calls"] += 1
                        
                except Exception:
                    with _lock:
                        _stats["api_errors"] += 1
                    cti_result = None

        cti_score = cti_result["score"] if cti_result else 0
        
        # Step 4: ALERT TYPE + RISK SCORE
        if ml_class == "MALICIOUS" and cti_result and cti_score > CTI_THRESHOLD:
            alert_type = "ML_CTI"
            risk_score = round((ml_prob * 0.7 + (cti_score / 100.0) * 0.3) * 100, 1)
        elif ml_class == "MALICIOUS" and (not cti_result or cti_score <= CTI_THRESHOLD):
            alert_type = "ML_ONLY"
            risk_score = round(ml_prob * 100, 1)
        elif ml_class == "BENIGN" and cti_result and cti_score > CTI_THRESHOLD:
            alert_type = "CTI_ONLY"
            risk_score = round((cti_score / 100.0) * 0.5 * 100, 1)
        else:
            alert_type = "NO_ALERT"
            risk_score = 0.0

        # Step 5: SET alert["cti_data"] and alert["risk_score"]
        if cti_result is not None:
            alert["cti_data"] = {
                "abuse_score": cti_result["score"],
                "country": cti_result["country"],
                "total_reports": cti_result["reports"],
                "alert_type": alert_type,
                "risk_score": risk_score,
                "lookup_ip": lookup_ip
            }
        else:
            alert["cti_data"] = {
                "abuse_score": None,
                "country": None,
                "total_reports": None,
                "alert_type": alert_type,
                "risk_score": risk_score,
                "lookup_ip": lookup_ip
            }
            
        alert["risk_score"] = risk_score
        
    except Exception:
        # On any error: return alert unchanged with cti_data=None
        alert["cti_data"] = None

    return alert
