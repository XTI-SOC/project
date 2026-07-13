import sqlite3
import json
import uuid
from datetime import datetime, timezone

_db_path = "alerts.db"

def _get_conn():
    conn = sqlite3.connect(_db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db(db_path: str = "alerts.db") -> None:
    global _db_path
    _db_path = db_path
    conn = _get_conn()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                confidence TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                duration_s REAL,
                ml_class TEXT,
                attack_type TEXT,
                ml_prob REAL,
                risk_score REAL,
                shap_json TEXT,
                cti_score INTEGER,
                cti_country TEXT,
                cti_status TEXT DEFAULT 'done',
                close_reason TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_type ON alerts(alert_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_score ON alerts(risk_score)")
        conn.commit()
    finally:
        conn.close()

def save_alert(alert: dict) -> str:
    alert_id = str(uuid.uuid4())
    alert["alert_id"] = alert_id
    
    cti = alert.get("cti_data") or {}
    alert_type = cti.get("alert_type", "NO_ALERT")
    
    if alert_type == "ML_CTI" or alert_type == "ARP_ANOMALY":
        confidence = "high"
    elif alert_type in ("ML_ONLY", "CORRELATION"):
        confidence = "medium"
    elif alert_type in ("CTI_ONLY", "RULE_BASED"):
        confidence = "low"
    else:
        confidence = "medium"
        
    shap_json = json.dumps(alert.get("shap_explanation", [])) if alert.get("shap_explanation") else None
    
    # Safe float extraction
    ts = alert.get("timestamp", 0)
    if isinstance(ts, (int, float)):
        ts_str = str(ts)
    else:
        ts_str = str(datetime.now(timezone.utc).timestamp())
        
    conn = _get_conn()
    try:
        conn.execute("""
            INSERT OR IGNORE INTO alerts (
                id, timestamp, alert_type, confidence,
                src_ip, dst_ip, src_port, dst_port,
                protocol, duration_s, ml_class, attack_type,
                ml_prob, risk_score, shap_json,
                cti_score, cti_country, cti_status, close_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_id,
            ts_str,
            alert_type,
            confidence,
            alert.get("src_ip"),
            alert.get("dst_ip"),
            alert.get("src_port"),
            alert.get("dst_port"),
            alert.get("protocol"),
            alert.get("duration_s"),
            alert.get("ml_class"),
            alert.get("attack_type"),
            alert.get("ml_probability"),
            alert.get("risk_score"),
            shap_json,
            cti.get("abuse_score"),
            cti.get("country"),
            cti.get("cti_status", "done"),
            alert.get("close_reason")
        ))
        conn.commit()
    finally:
        conn.close()
        
    return alert_id

def update_cti(alert_id: str, alert: dict) -> None:
    cti = alert.get("cti_data") or {}
    alert_type = cti.get("alert_type", "NO_ALERT")
    
    if alert_type == "ML_CTI" or alert_type == "ARP_ANOMALY":
        confidence = "high"
    elif alert_type in ("ML_ONLY", "CORRELATION"):
        confidence = "medium"
    elif alert_type in ("CTI_ONLY", "RULE_BASED"):
        confidence = "low"
    else:
        confidence = "medium"
        
    conn = _get_conn()
    try:
        conn.execute("""
            UPDATE alerts
            SET alert_type=?, risk_score=?, cti_score=?,
                cti_country=?, cti_status='done', confidence=?
            WHERE id=?
        """, (
            alert_type,
            alert.get("risk_score"),
            cti.get("abuse_score"),
            cti.get("country"),
            confidence,
            alert_id
        ))
        conn.commit()
    finally:
        conn.close()

def get_recent_alerts(limit: int = 50) -> list:
    conn = _get_conn()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("""
            SELECT * FROM alerts
            ORDER BY risk_score DESC, timestamp DESC
            LIMIT ?
        """, (limit,))
        
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict["alert_id"] = row_dict.pop("id")
            
            # Map back to structured cti_data roughly
            row_dict["cti_data"] = {
                "alert_type": row_dict.pop("alert_type"),
                "abuse_score": row_dict.pop("cti_score"),
                "country": row_dict.pop("cti_country"),
                "cti_status": row_dict.pop("cti_status"),
                # dummy lookup_ip
                "lookup_ip": row_dict.get("dst_ip")
            }
            
            # Additional remapping to match typical alert schema
            row_dict["timestamp"] = float(row_dict["timestamp"])
            row_dict["ml_probability"] = row_dict.pop("ml_prob")
            
            shap = row_dict.pop("shap_json")
            if shap:
                try:
                    row_dict["shap_explanation"] = json.loads(shap)
                except Exception:
                    row_dict["shap_explanation"] = None
            else:
                row_dict["shap_explanation"] = None
                
            results.append(row_dict)
        return results
    finally:
        conn.close()

def get_stats() -> dict:
    conn = _get_conn()
    try:
        cursor = conn.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN ml_class = 'MALICIOUS' THEN 1 ELSE 0 END) as malicious,
                SUM(CASE WHEN confidence = 'low' THEN 1 ELSE 0 END) as benign_flagged,
                SUM(CASE WHEN confidence = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN confidence = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN confidence = 'low' THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN cti_status = 'pending' THEN 1 ELSE 0 END) as pending_cti
            FROM alerts
        """)
        row = cursor.fetchone()
        
        import os
        size_mb = os.path.getsize(_db_path) / (1024 * 1024) if os.path.exists(_db_path) else 0
        
        return {
            "total": row[0] or 0,
            "malicious": row[1] or 0,
            "benign_flagged": row[2] or 0,
            "high": row[3] or 0,
            "medium": row[4] or 0,
            "low": row[5] or 0,
            "pending_cti": row[6] or 0,
            "size_mb": size_mb
        }
    finally:
        conn.close()
