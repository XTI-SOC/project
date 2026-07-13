const isBrowser = typeof window !== "undefined";
const hostname = isBrowser ? window.location.hostname : "127.0.0.1";

export const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? `http://${hostname}:8000`;
export const API_KEY  = process.env.NEXT_PUBLIC_API_KEY ?? "xti_soc_secure_2024";
export const WS_URL   = process.env.NEXT_PUBLIC_WS_URL ?? `ws://${hostname}:8000/ws`;

export interface ShapFeature {
  feature: string
  shap_value: number
}

export interface CtiData {
  abuse_score:    number | null
  country:        string | null
  total_reports:  number | null
  alert_type:     "ML_CTI" | "ML_ONLY" | "CTI_ONLY" | "NO_ALERT" | "CORRELATION" | "RULE_BASED"
  risk_score:     number
  lookup_ip:      string | null
  cti_status:     "pending" | "done"
}

export interface Alert {
  alert_id:         string
  timestamp:        number
  src_ip:           string
  dst_ip:           string
  src_port:         number
  dst_port:         number
  protocol:         string
  duration_s:       number
  ml_class:         "BENIGN" | "MALICIOUS"
  attack_type:      string
  ml_probability:   number
  risk_score:       number
  shap_explanation: ShapFeature[] | null
  cti_data:         CtiData | null
  close_reason:     string
  fwd_packets:      number
  bwd_packets:      number
  total_bytes:      number
}

export interface Stats {
  db: {
    total: number
    malicious: number
    benign_flagged: number
    high: number
    medium: number
    low: number
    pending_cti: number
    size_mb: number
  }
  engine: any
  cti: any
  server: any
}

export async function fetchAlerts(limit = 50): Promise<Alert[]> {
  const res = await fetch(`${API_BASE}/alerts?limit=${limit}`, {
    headers: { "X-API-Key": API_KEY }
  })
  if (!res.ok) throw new Error("Failed to fetch alerts")
  return res.json()
}

// Keeping this for generic use, but we will use SWR in components to fetch it
export async function fetchStats(url: string = `${API_BASE}/stats`): Promise<Stats> {
  const res = await fetch(url, {
    headers: { "X-API-Key": API_KEY }
  })
  if (!res.ok) throw new Error("Failed to fetch stats")
  return res.json()
}
