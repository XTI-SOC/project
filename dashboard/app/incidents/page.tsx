"use client"
import { useEffect, useState } from "react"
import { fetchAlerts, WS_URL } from "@/lib/api"
import type { Alert } from "@/lib/api"
import { Header } from "@/components/Header"

export default function IncidentsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [wsStatus, setWsStatus] = useState<"connecting"|"open"|"closed">("connecting")
  const [activeTab, setActiveTab] = useState<"All Incidents"|"Active"|"Resolved">("All Incidents")
  
  useEffect(() => {
    fetchAlerts(100).then(setAlerts).catch(console.error)
    
    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout;

    const connectWebSocket = () => {
      ws = new WebSocket(WS_URL)
      
      ws.onopen = () => setWsStatus("open")
      
      ws.onclose = () => {
        setWsStatus("closed")
        reconnectTimeout = setTimeout(connectWebSocket, 2000)
      }
      
      ws.onerror = () => {
        setWsStatus("closed")
        ws?.close()
      }
      
      ws.onmessage = (e) => {
        const incoming: Alert = JSON.parse(e.data)
        setAlerts(prev => {
          const idx = prev.findIndex(a => a.alert_id === incoming.alert_id)
          if (idx !== -1) {
            const next = [...prev]
            next[idx] = incoming
            return next
          }
          return [incoming, ...prev].slice(0, 100)
        })
      }
    }

    connectWebSocket()

    return () => {
      clearTimeout(reconnectTimeout)
      if (ws) {
        ws.onclose = null // prevent reconnect on unmount
        ws.close()
      }
    }
  }, [])
  
  // Create simulated "Incidents" basically mapping from High Risk alerts
  let incidents = alerts.filter(a => a.risk_score >= 40)
  
  // Apply tab filtering: Simulate Resolved as older than 1 hour (3600s), Active as < 1 hour
  if (activeTab === "Active") {
      incidents = incidents.filter(i => (Date.now() / 1000) - i.timestamp < 3600)
  } else if (activeTab === "Resolved") {
      incidents = incidents.filter(i => (Date.now() / 1000) - i.timestamp >= 3600)
  }
  
  const criticalCount = alerts.filter(i => i.risk_score >= 80).length
  const activeCount = alerts.filter(a => a.risk_score >= 40 && (Date.now() / 1000) - a.timestamp < 3600).length

  return (
    <>
      <Header wsStatus={wsStatus} />
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
                        {["All Incidents", "Active", "Resolved"].map(tab => (
                            <button 
                                key={tab}
                                onClick={() => setActiveTab(tab as any)}
                                className={`px-4 py-1.5 text-xs font-bold tracking-widest uppercase rounded-sm transition-colors ${activeTab === tab ? 'bg-surface-container-highest border-b border-primary-fixed text-on-surface' : 'text-slate-500 hover:text-on-surface'}`}
                            >
                                {tab}
                            </button>
                        ))}
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
                                                {isCritical && activeTab !== "Resolved" && <span className="w-2 h-2 rounded-full bg-error animate-pulse"></span>}
                                                {activeTab === "Resolved" || ((Date.now() / 1000) - inc.timestamp >= 3600) ? "Resolved" : isCritical ? "In Progress" : "Open"}
                                            </div>
                                        </td>
                                        <td className="px-6 py-5 font-mono text-xs text-outline-variant">
                                            {Math.floor(((Date.now() / 1000) - inc.timestamp) / 60)}m
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
