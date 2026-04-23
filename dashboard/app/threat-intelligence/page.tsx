"use client"
import { useEffect, useState } from "react"
import type { Alert } from "@/lib/api"
import { fetchAlerts } from "@/lib/api"
import { Header } from "@/components/Header"

export default function ThreatIntelligencePage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  
  useEffect(() => {
    fetchAlerts(100).then(setAlerts).catch(console.error)
  }, [])
  
  return (
      <>
        <Header wsStatus="open" />
        <main className="lg:pl-64 pt-20 p-6 min-h-screen">
        <div className="grid grid-cols-12 gap-6">
          <div className="col-span-12 lg:col-span-8 space-y-6">
            <section className="bg-surface-container-low rounded-lg p-6 relative overflow-hidden">
                <div className="absolute top-0 right-0 p-4 opacity-10">
                    <span className="material-symbols-outlined text-8xl">query_stats</span>
                </div>
                <div className="relative z-10">
                    <h2 className="headline text-2xl font-bold mb-2">Indicator Lookup</h2>
                    <p className="text-sm text-secondary mb-6 max-w-md">Query the XTI-SOC decentralized intelligence network for malicious activity patterns across known adversarial clusters.</p>
                    <div className="flex flex-wrap gap-4">
                        <div className="flex-1 min-w-[300px] flex items-center bg-surface-container-highest rounded p-1 border-b border-transparent focus-within:border-primary transition-all">
                            <span className="px-3 text-secondary text-xs uppercase font-bold border-r border-outline-variant/20">Type: ANY</span>
                            <input className="bg-transparent border-none focus:ring-0 flex-1 text-sm font-mono outline-none ml-2" placeholder="Paste IP, URL, SHA-256 or Domain..." type="text"/>
                            <button className="px-6 py-2 bg-primary text-on-primary font-bold text-xs rounded-sm hover:brightness-110">ANALYZE</button>
                        </div>
                    </div>
                </div>
            </section>
            
            <section className="bg-surface-container rounded-lg flex flex-col h-[500px]">
                <div className="px-6 py-4 border-b border-outline-variant/10 flex justify-between items-center bg-surface-container-high/50">
                    <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined text-primary">reorder</span>
                        <h3 className="font-headline font-bold text-sm tracking-wide">GLOBAL THREAT FEED</h3>
                    </div>
                    <div className="flex items-center gap-4 text-[10px] text-secondary">
                        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-error animate-pulse"></span>LIVE</span>
                        <span className="px-2 py-0.5 rounded bg-surface-container-highest border border-outline-variant/20">LIVE STREAM</span>
                    </div>
                </div>
                <div className="flex-1 overflow-y-auto p-0 scrollbar-hide">
                    <table className="w-full text-left border-collapse">
                        <thead className="sticky top-0 bg-surface-container-high text-[10px] uppercase text-secondary font-bold z-10">
                            <tr>
                                <th className="px-6 py-3">Timestamp</th>
                                <th className="px-6 py-3">IOC Value</th>
                                <th className="px-6 py-3">Type</th>
                                <th className="px-6 py-3 text-right">Risk Score</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-outline-variant/5">
                            {alerts.map(a => (
                                <tr key={a.alert_id} className="hover:bg-primary-dim/10 group transition-colors cursor-pointer bg-surface-container-lowest">
                                    <td className="px-6 py-3 text-[11px] font-mono text-secondary">{new Date(a.timestamp).toISOString()}</td>
                                    <td className="px-6 py-3 text-[12px] font-mono font-medium">{a.src_ip}</td>
                                    <td className="px-6 py-3 text-[10px]"><span className="px-2 py-0.5 rounded bg-surface-container-highest text-primary">IPV4</span></td>
                                    <td className="px-6 py-3 text-right"><span className="text-error font-headline font-bold">{a.risk_score.toFixed(1)}/100</span></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </section>
          </div>
          
          <div className="col-span-12 lg:col-span-4 space-y-6">
            <section className="bg-surface-container-high rounded-lg p-6 border border-outline-variant/10 shadow-xl">
                <div className="flex justify-between items-center mb-6">
                    <h3 className="font-headline font-bold text-sm tracking-wider uppercase text-on-surface-variant">Top Threat Actors</h3>
                    <span className="text-[10px] bg-error-container text-on-error-container px-2 py-0.5 rounded font-bold">CRITICAL WATCH</span>
                </div>
                <div className="space-y-4">
                    <div className="p-4 bg-surface-container-low rounded border-l-4 border-error flex items-center justify-between group hover:bg-surface-container transition-all">
                        <div>
                            <h4 className="font-headline font-bold text-base group-hover:text-primary transition-colors">Lazarus Group</h4>
                            <p className="text-[10px] text-secondary">APT38 | North Korean Nexus</p>
                        </div>
                        <div className="text-right">
                            <div className="text-2xl font-headline font-bold text-error">9.8</div>
                        </div>
                    </div>
                    <div className="p-4 bg-surface-container-low rounded border-l-4 border-tertiary-fixed flex items-center justify-between group hover:bg-surface-container transition-all">
                        <div>
                            <h4 className="font-headline font-bold text-base group-hover:text-primary transition-colors">Fancy Bear</h4>
                            <p className="text-[10px] text-secondary">APT28 | Russian Nexus</p>
                        </div>
                        <div className="text-right">
                            <div className="text-2xl font-headline font-bold text-tertiary-fixed">8.4</div>
                        </div>
                    </div>
                </div>
            </section>
          </div>
        </div>
        </main>
      </>
  )
}
