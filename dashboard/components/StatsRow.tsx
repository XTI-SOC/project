"use client"
import type { Stats } from "@/lib/api"

export function StatsRow({ stats }: { stats: Stats | null }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
      <div className="bg-surface-container-low p-5 rounded-lg border-l-2 border-primary shadow-lg">
        <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Total Alerts</div>
        <div className="flex items-end gap-3">
          <span className="text-4xl font-headline font-bold text-on-surface">{stats?.total ?? "—"}</span>
        </div>
      </div>
      <div className="bg-surface-container-low p-5 rounded-lg border-l-2 border-error shadow-lg">
        <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1 text-error/60">Malicious</div>
        <div className="flex items-end gap-3">
          <span className="text-4xl font-headline font-bold text-error">{stats?.malicious ?? "—"}</span>
          <span className="text-error-dim text-xs font-mono mb-1">CRITICAL</span>
        </div>
      </div>
      <div className="bg-surface-container-low p-5 rounded-lg border-l-2 border-tertiary shadow-lg">
        <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1 text-tertiary/60">High Risk</div>
        <div className="flex items-end gap-3">
          <span className="text-4xl font-headline font-bold text-[#f97316]">{stats?.high ?? "—"}</span>
          <span className="text-tertiary-dim text-xs font-mono mb-1">PRIORITY 1</span>
        </div>
      </div>
      <div className="bg-surface-container-low p-5 rounded-lg border-l-2 border-yellow-500 shadow-lg">
        <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1 text-yellow-500/60">Pending CTI</div>
        <div className="flex items-end gap-3">
          <span className="text-4xl font-headline font-bold text-[#eab308]">{stats?.pending_cti ?? "—"}</span>
          <span className="text-yellow-200 text-xs font-mono mb-1">ENRICHING</span>
        </div>
      </div>
    </div>
  )
}
