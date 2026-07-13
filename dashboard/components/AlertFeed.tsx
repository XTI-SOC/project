"use client"
import { useState } from "react"
import type { Alert } from "@/lib/api"
import { AlertCard } from "./AlertCard"

export function AlertFeed({ alerts }: { alerts: Alert[] }) {
  const [sortBy, setSortBy] = useState<"newest" | "highest_risk">("highest_risk")

  const sortedAlerts = [...alerts].sort((a, b) => {
    if (sortBy === "highest_risk") {
      const riskDiff = (b.risk_score || 0) - (a.risk_score || 0)
      if (riskDiff !== 0) return riskDiff
      return b.timestamp - a.timestamp
    }
    return b.timestamp - a.timestamp
  })

  return (
    <div className="lg:w-2/3">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-3 h-3 rounded-full bg-error pulse-red"></div>
        <h2 className="font-headline font-bold text-xl tracking-tight">LIVE THREAT STREAM</h2>
        <div className="h-[1px] flex-1 bg-gradient-to-r from-outline-variant/30 to-transparent"></div>
        
        {/* Added priority sorter mapped nicely to the design */}
        <div className="flex bg-surface-container-low rounded p-1 ml-4 border border-outline-variant/10">
          <button
            onClick={() => setSortBy("newest")}
            className={`px-4 py-1 rounded-sm transition-colors text-[10px] uppercase font-bold tracking-wider 
              ${sortBy === "newest" ? "bg-surface text-on-surface border border-outline-variant/20" : "text-slate-500 hover:text-slate-300"}`}
          >
            Newest
          </button>
          <button
            onClick={() => setSortBy("highest_risk")}
            className={`px-4 py-1 rounded-sm transition-colors text-[10px] uppercase font-bold tracking-wider 
              ${sortBy === "highest_risk" ? "bg-surface text-on-surface border border-outline-variant/20" : "text-slate-500 hover:text-slate-300"}`}
          >
            Highest Risk
          </button>
        </div>
      </div>
      <div className="grid grid-cols-1 gap-4">
        {alerts.length === 0 ? (
          <div className="bg-surface-container-high border border-outline-variant/10 rounded-sm p-12 text-center text-slate-400">
             Listening for intelligence hooks... Open the Python Pipeline side.
          </div>
        ) : (
          sortedAlerts.map(a => <AlertCard key={a.alert_id} alert={a} />)
        )}
      </div>
    </div>
  )
}
