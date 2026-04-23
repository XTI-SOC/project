"use client"
import { useEffect, useState } from "react"
import { fetchAlerts } from "@/lib/api"
import type { Alert } from "@/lib/api"
import { Header } from "@/components/Header"

export default function IncidentsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  
  useEffect(() => {
    fetchAlerts(100).then(setAlerts).catch(console.error)
  }, [])
  
  // Create simulated "Incidents" basically mapping from High Risk alerts
  const incidents = alerts.filter(a => a.risk_score >= 40)
  
  const criticalCount = incidents.filter(i => i.risk_score >= 80).length
  const activeCount = incidents.length

  return (
    <>
      <Header wsStatus="open" />
      <main className="md:pl-64 pt-16 h-screen flex flex-col">
        <div className="flex flex-1 overflow-hidden">
            <section className="flex-1 overflow-y-auto p-6 bg-surface">
                <header className="mb-8">
                    <h1 className="text-4xl font-bold headline tracking-tight mb-2">Security Incidents</h1>
                    <div className="flex gap-4">
                    <span className="text-sm text-outline-variant font-mono">Active Sessions: {activeCount}</span>
                    <span className="text-sm text-error font-mono">Critical Alerts: {criticalCount}</span>
                    </div>
                </header>
                
                <div className="flex items-center justify-between mb-6 bg-surface-container-low p-2 rounded-lg">
                    <div className="flex gap-2">
                        <button className="px-4 py-1.5 bg-surface-container-highest text-xs font-bold tracking-widest uppercase rounded-sm border-b border-primary-fixed">All Incidents</button>
                        <button className="px-4 py-1.5 text-slate-500 text-xs font-bold tracking-widest uppercase hover:text-on-surface">Active</button>
                        <button className="px-4 py-1.5 text-slate-500 text-xs font-bold tracking-widest uppercase hover:text-on-surface">Resolved</button>
                    </div>
                    <div className="flex items-center gap-4">
                        <span className="material-symbols-outlined text-outline cursor-pointer hover:text-primary transition-colors">filter_list</span>
                        <span className="material-symbols-outlined text-outline cursor-pointer hover:text-primary transition-colors">download</span>
                    </div>
                </div>
                
                <div className="bg-surface-container rounded-xl overflow-hidden shadow-2xl">
                    <table className="w-full text-left border-collapse">
                        <thead>
                        <tr className="bg-surface-container-high/50 border-b border-outline-variant/10">
                            <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-outline">Severity</th>
                            <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-outline">ID</th>
                            <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-outline">Incident Name</th>
                            <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-outline">Analyst</th>
                            <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-outline">Status</th>
                            <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-outline">Duration</th>
                        </tr>
                        </thead>
                        <tbody className="divide-y divide-outline-variant/5">
                            {incidents.map(inc => {
                                const isCritical = inc.risk_score >= 80;
                                return (
                                    <tr key={inc.alert_id} className={`hover:bg-primary-dim/10 transition-colors cursor-pointer group ${isCritical ? "bg-error-container/5" : ""}`}>
                                        <td className="px-6 py-5">
                                            {isCritical ? (
                                                <span className="inline-block px-2 py-0.5 bg-error-container text-on-error-container text-[10px] font-bold rounded-sm">CRITICAL</span>
                                            ) : (
                                                <span className="inline-block px-2 py-0.5 bg-tertiary-fixed text-on-tertiary-fixed-variant text-[10px] font-bold rounded-sm">HIGH</span>
                                            )}
                                        </td>
                                        <td className="px-6 py-5 font-mono text-xs text-primary">#{inc.alert_id.substring(0, 8).toUpperCase()}</td>
                                        <td className="px-6 py-5 font-medium">{inc.attack_type} detected on {inc.dst_ip}</td>
                                        <td className="px-6 py-5">
                                            <span className="text-xs italic text-outline">Unassigned</span>
                                        </td>
                                        <td className="px-6 py-5">
                                            <div className="flex items-center gap-2 text-xs text-on-surface font-mono">
                                                {isCritical && <span className="w-2 h-2 rounded-full bg-error animate-pulse"></span>}
                                                {isCritical ? "In Progress" : "Open"}
                                            </div>
                                        </td>
                                        <td className="px-6 py-5 font-mono text-xs text-outline-variant">
                                            {Math.floor((Date.now() - inc.timestamp) / 60000)}m
                                        </td>
                                    </tr>
                                )
                            })}
                        </tbody>
                    </table>
                </div>
            </section>
            
            <aside className="w-[420px] bg-surface-container-low border-l border-outline-variant/10 flex flex-col hidden xl:flex">
                <div className="p-6 border-b border-outline-variant/10 bg-surface-container-high/30 backdrop-blur-md">
                    <div className="flex justify-between items-start mb-4">
                        <span className="text-[10px] font-mono text-primary">CASE_ID // SELECT_INCIDENT</span>
                        <button className="text-outline hover:text-on-surface"><span className="material-symbols-outlined">close</span></button>
                    </div>
                    <h2 className="text-xl font-bold headline leading-tight mb-2">Select an Incident to view details</h2>
                </div>
            </aside>
        </div>
      </main>
    </>
  )
}
