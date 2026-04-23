"use client"
import type { Alert } from "@/lib/api"
import { ShapChart } from "./ShapChart"

export function AlertCard({ alert: a }: { alert: Alert }) {
  const cti = a.cti_data

  const isPending = cti?.cti_status === "pending"
  const isCtiOnly = cti?.alert_type === "CTI_ONLY"
  
  // High risk / Critical (80+) -> Red
  // Medium risk / High (40-80) -> Orange
  // Low risk / Medium (<40 but malicious) -> Gray/Unknown
  
  let borderColor = "border-[#475569]"
  let scoreColor = "text-[#f97316]"
  
  if (a.risk_score >= 80) {
    borderColor = "border-error"
    scoreColor = "text-error"
  } else if (a.risk_score >= 40) {
    borderColor = "border-[#f97316]"
    scoreColor = "text-[#f97316]"
  }

  // Handle CTI Only or Pending visual states
  if (isPending) {
    return (
      <div className="bg-surface-container-high border-l-[4px] border-primary-container rounded-sm overflow-hidden flex flex-col md:flex-row shadow-xl opacity-80">
        <div className="p-6 md:w-1/4 border-r border-outline-variant/10">
          <div className="flex gap-2 mb-4">
            <span className="bg-primary-container text-on-primary-container px-2 py-0.5 text-[9px] font-bold rounded-sm uppercase tracking-tighter">
              {a.ml_class === "MALICIOUS" ? "ML ONLY" : "BENIGN"}
            </span>
            <span className="bg-outline-variant/30 text-on-surface px-2 py-0.5 text-[9px] font-bold rounded-sm border border-outline-variant/50 uppercase tracking-tighter">
              {a.attack_type === "BENIGN" ? "TEST" : a.attack_type}
            </span>
          </div>
          <div className="w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center animate-pulse">
            <span className="material-symbols-outlined text-primary">query_stats</span>
          </div>
        </div>
        <div className="p-6 flex-1 flex items-center justify-center">
          <div className="flex items-center gap-4">
            <div className="w-5 h-5 border-2 border-yellow-500 border-t-transparent rounded-full animate-spin"></div>
            <span className="text-[11px] font-mono text-yellow-500 tracking-widest uppercase">CTI reputation lookup in progress...</span>
          </div>
        </div>
      </div>
    )
  }

  if (isCtiOnly) {
    return (
      <div className="bg-surface-container-high border-l-[4px] border-[#475569] rounded-sm overflow-hidden flex flex-col md:flex-row shadow-xl hover:bg-surface-container-highest transition-colors">
        <div className="p-6 md:w-1/4 border-r border-outline-variant/10">
          <div className="flex gap-2 mb-4">
            <span className="bg-slate-700 text-slate-300 px-2 py-0.5 text-[9px] font-bold rounded-sm uppercase tracking-tighter">CTI ONLY</span>
            <span className="bg-slate-800 text-slate-500 px-2 py-0.5 text-[9px] font-bold rounded-sm border border-slate-700 uppercase tracking-tighter">{a.attack_type}</span>
          </div>
          <div className="font-mono text-sm text-slate-400">{a.src_ip}:{a.src_port}</div>
          <div className="flex py-1 text-slate-700">→</div>
          <div className="font-mono text-sm text-slate-400">{a.dst_ip}:{a.dst_port}</div>
        </div>
        <div className="p-6 flex-1 flex items-center">
          <div className="bg-surface-container-lowest p-4 w-full border border-outline-variant/10 rounded-sm flex items-center gap-4">
            <span className="material-symbols-outlined text-slate-500">info</span>
            <span className="text-xs text-slate-300 font-mono tracking-tight">Reputation-based alert only. Analysis context suppressed due to low confidence score from ML engine.</span>
          </div>
        </div>
      </div>
    )
  }

  // Normal / High Risk Alert Card
  return (
    <div className={`bg-surface-container-high border-l-[4px] ${borderColor} rounded-sm overflow-hidden flex flex-col md:flex-row shadow-xl hover:bg-surface-container-highest transition-colors`}>
      <div className="p-6 md:w-1/4 border-r border-outline-variant/10">
        <div className="flex gap-2 mb-4">
          <span className={`${cti?.alert_type === "ML_CTI" ? "bg-error/20 text-error border-error/30" : "bg-[#f97316]/20 text-[#f97316] border-[#f97316]/30"} px-2 py-0.5 text-[9px] font-bold rounded-sm border uppercase tracking-tighter`}>
            {cti?.alert_type === "ML_CTI" ? "ML+CTI" : "ML ONLY"}
          </span>
          <span className={`${a.attack_type === "DDoS" ? "bg-error text-on-error" : "bg-purple-900/40 text-purple-400 border border-purple-500/30"} px-2 py-0.5 text-[9px] font-bold rounded-sm uppercase tracking-tighter`}>
            {a.attack_type}
          </span>
        </div>
        <div className="space-y-1 mb-4">
          <div className="text-[10px] text-slate-500 uppercase font-bold tracking-widest">{a.attack_type === "DDoS" ? "Source Entity" : "Target Path"}</div>
          <div className="font-mono text-sm text-on-surface">{a.src_ip}:{a.src_port}</div>
          <div className="flex justify-center py-1">
            <span className="material-symbols-outlined text-slate-600 text-sm">arrow_downward</span>
          </div>
          <div className="font-mono text-sm text-on-surface">{a.dst_ip}:{a.dst_port}</div>
        </div>
        <div className="bg-surface-container-lowest p-3 rounded-sm border border-outline-variant/5">
          <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Aggregated Risk</div>
          <div className={`text-2xl font-headline font-bold ${scoreColor}`}>{a.risk_score.toFixed(1)}<span className="text-xs text-slate-600">/100</span></div>
        </div>
      </div>
      
      <div className="p-6 flex-1 flex flex-col md:flex-row gap-6">
        <div className="flex-1">
          {a.shap_explanation && a.shap_explanation.length > 0 && (
             <div className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mb-4 flex items-center gap-2">
               <span className="material-symbols-outlined text-xs">auto_awesome</span> SHAP Feature Explanations
             </div>
          )}
          {a.shap_explanation && a.shap_explanation.length > 0 && (
             <ShapChart data={a.shap_explanation} alertColor={scoreColor} />
          )}
        </div>
        
        {/* CTI Box */}
        {cti?.abuse_score !== null && cti?.abuse_score !== undefined ? (
          <div className="w-full md:w-1/3 bg-surface-container-lowest/50 p-4 rounded-sm border border-error/10">
            <div className="text-[10px] text-error font-bold uppercase tracking-widest mb-3">Threat Intel (CTI)</div>
            <div className="space-y-3">
              <div className="flex justify-between items-center border-b border-outline-variant/10 pb-2">
                <span className="text-[10px] text-slate-400">Source Reputation</span>
                <span className="font-mono text-[11px] text-error font-bold">ABUSE {cti.abuse_score}/100</span>
              </div>
              <div className="flex justify-between items-center border-b border-outline-variant/10 pb-2">
                <span className="text-[10px] text-slate-400">Geo Origin</span>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono">{cti.country || "UNKNOWN"}</span>
                </div>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[10px] text-slate-400">IP Records</span>
                <span className="font-mono text-[11px] text-on-surface">{cti.total_reports || 0}</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="w-full md:w-1/3 flex items-center justify-center border-2 border-dashed border-outline-variant/20 rounded-sm">
            <div className="text-center p-4">
              <span className="material-symbols-outlined text-slate-600 mb-2">lock_reset</span>
              <div className="text-[10px] text-slate-500 font-mono italic">Private IP &mdash; no CTI data</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
