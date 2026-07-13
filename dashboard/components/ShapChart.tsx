"use client"
import type { ShapFeature } from "@/lib/api"

const FEATURE_EXPLANATIONS: Record<string, string> = {
  "TotLen Fwd Pkts": "Unusually high volume of data transmitted by the attacker.",
  "Flow IAT Mean": "Suspiciously rapid or consistent packet timing (often indicates automated scanning or bots).",
  "Tot Bwd Pkts": "Abnormal number of response packets, typical of reflective or flood attacks.",
  "Flow Byts/s": "Extremely high data transfer rate, often seen in data exfiltration or volumetric DDoS.",
  "Flow Duration": "Connection duration is anomalous (either a split-second scan or a long-polling C2 connection).",
  "Fwd Pkt Len Max": "Attacker sent an unusually large single packet, typical of buffer overflow attempts.",
  "Bwd Pkt Len Max": "Target responded with an unusually large packet, suggesting successful data theft.",
  "Fwd Pkt Len Mean": "Average size of packets sent matches known malware payloads.",
  "Bwd Pkt Len Mean": "Average size of response packets is highly anomalous.",
  "Fwd Pkts/s": "Attacker is sending packets at an extremely high frequency (Flood).",
  "Bwd Pkts/s": "Target is responding at a high frequency, typical of amplified DDoS.",
  "Flow Pkts/s": "Overall packet frequency across the connection is abnormally high.",
  "Down/Up Ratio": "Suspicious ratio between downloaded and uploaded data (potential exfiltration).",
  "Init Fwd Win Byts": "Anomalous initial TCP window size, a common fingerprint of port scanners like Nmap.",
  "Init Bwd Win Byts": "Anomalous initial TCP window size from the target.",
  "Fwd Seg Size Min": "Suspicious minimum segment size, often altered by evasion tools.",
  "Active Mean": "Connection activity pattern matches automated scripts rather than human users.",
  "Idle Mean": "Connection idle times are suspiciously regular, suggesting a beaconing C2 botnet.",
}

function getExplanation(feature: string): string {
  if (FEATURE_EXPLANATIONS[feature]) return FEATURE_EXPLANATIONS[feature];
  for (const [key, val] of Object.entries(FEATURE_EXPLANATIONS)) {
    if (feature.toLowerCase().includes(key.toLowerCase())) return val;
  }
  // Rule-based engines inject long English strings directly
  if (feature.includes(" ") && feature.length > 15) return feature;
  return `Anomalous behavior detected in network metric: ${feature}.`;
}

export function ShapChart({ data, alertColor }: { data: ShapFeature[], alertColor?: string }) {
  // We only care about features that pushed the score towards MALICIOUS (positive SHAP values)
  const sorted = [...data]
    .filter(f => f.shap_value > 0)
    .sort((a, b) => b.shap_value - a.shap_value)
    .slice(0, 3) // Display top 3 critical reasons

  if (sorted.length === 0) {
     return (
       <div className="w-full bg-surface-container p-4 rounded-sm border border-outline-variant/10 shadow-inner flex items-center justify-center min-h-[160px]">
          <span className="text-slate-400 text-xs italic font-mono">No strong malicious indicators isolated.</span>
       </div>
     )
  }

  return (
    <div className="w-full bg-surface-container p-4 rounded-sm border border-outline-variant/10 shadow-inner flex flex-col gap-4 min-h-[160px] justify-center">
      {sorted.map((entry, index) => (
        <div key={index} className="flex gap-3 items-start">
           <div className="mt-0.5">
              <span className={`material-symbols-outlined text-sm ${alertColor || "text-error"}`}>emergency</span>
           </div>
           <div>
              <div className="text-slate-300 text-[11px] leading-relaxed">
                 {getExplanation(entry.feature)}
              </div>
              <div className="text-[9px] text-slate-500 font-mono mt-1 uppercase tracking-widest">
                 {entry.feature.includes(" ") && entry.feature.length > 15 ? "RULE TRIGGER: " : "INDICATOR: "} {entry.feature} <span className={alertColor || "text-error"}>({(entry.shap_value * 100).toFixed(1)}% IMPACT)</span>
              </div>
           </div>
        </div>
      ))}
    </div>
  )
}
