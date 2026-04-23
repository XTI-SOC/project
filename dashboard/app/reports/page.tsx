"use client"
import { Header } from "@/components/Header"
import { useEffect, useState } from "react"
import { fetchAlerts } from "@/lib/api"
import type { Alert } from "@/lib/api"

export default function ReportsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  
  useEffect(() => {
    fetchAlerts(50).then(setAlerts).catch(console.error)
  }, [])
  
  return (
      <>
        <Header wsStatus="open" />
        <main className="lg:pl-64 pt-20 p-6 min-h-screen">
            <header className="mb-8 flex justify-between items-end">
                <div>
                    <h1 className="text-4xl font-bold headline tracking-tight mb-2">Generated Reports</h1>
                    <p className="text-sm text-outline-variant font-mono">Automated PDF outputs for SOC shifts and C-level executives.</p>
                </div>
                <button className="bg-primary text-on-primary px-6 py-3 rounded-sm font-bold text-xs uppercase tracking-widest hover:brightness-110 shadow-lg shadow-primary/20">
                    Generate New Report
                </button>
            </header>
            
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                 {/* Reports List */}
                <div className="lg:col-span-2 space-y-4">
                    <div className="bg-surface-container-high rounded-lg p-5 border-l-4 border-primary flex items-center justify-between group hover:bg-surface-container-highest transition-colors cursor-pointer">
                        <div className="flex items-center gap-4">
                            <span className="material-symbols-outlined text-4xl text-primary font-light">picture_as_pdf</span>
                            <div>
                                <h3 className="font-headline font-bold text-lg mb-1 group-hover:text-primary transition-colors">Daily Shift Summary (Alpha)</h3>
                                <div className="text-[10px] text-slate-500 font-mono">Generated: 2023-11-24 18:00:00 UTC | Analyst: J. Vance</div>
                            </div>
                        </div>
                        <span className="material-symbols-outlined text-secondary group-hover:text-primary">download</span>
                    </div>

                    <div className="bg-surface-container-high rounded-lg p-5 border-l-4 border-error flex items-center justify-between group hover:bg-surface-container-highest transition-colors cursor-pointer">
                        <div className="flex items-center gap-4">
                            <span className="material-symbols-outlined text-4xl text-error font-light">picture_as_pdf</span>
                            <div>
                                <h3 className="font-headline font-bold text-lg mb-1 group-hover:text-error transition-colors">Incident Deep Dive: SQL Cluster 04</h3>
                                <div className="text-[10px] text-slate-500 font-mono">Generated: 2023-11-24 16:30:12 UTC | Auto-Generated Incident Report</div>
                            </div>
                        </div>
                        <span className="material-symbols-outlined text-secondary group-hover:text-error">download</span>
                    </div>

                    <div className="bg-surface-container-high rounded-lg p-5 border-l-4 border-outline-variant flex items-center justify-between group hover:bg-surface-container-highest transition-colors cursor-pointer">
                        <div className="flex items-center gap-4">
                            <span className="material-symbols-outlined text-4xl text-outline-variant font-light">picture_as_pdf</span>
                            <div>
                                <h3 className="font-headline font-bold text-lg mb-1">Weekly Executive Threat Brief</h3>
                                <div className="text-[10px] text-slate-500 font-mono">Generated: 2023-11-20 00:00:00 UTC | System Scheduled</div>
                            </div>
                        </div>
                        <span className="material-symbols-outlined text-secondary group-hover:text-on-surface">download</span>
                    </div>
                </div>

                <div className="bg-surface-container p-6 rounded-lg border border-outline-variant/10 flex flex-col">
                    <h3 className="font-headline font-bold text-xs uppercase tracking-widest mb-4">GLOBAL THREAT MAP</h3>
                    <div className="flex-1 relative bg-[#060e20] rounded-sm overflow-hidden min-h-[200px]">
                        <img className="absolute inset-0 w-full h-full object-cover opacity-40 grayscale" src="https://lh3.googleusercontent.com/aida-public/AB6AXuAH3IxlESgGieYS1Pn-E7I0lFdithKa2GVnet9I6dt3mx1wE2E6uYjwKpaOF-2mdNQ8NS2tT5Oscy8PNdbB3Vq2pEBfDdjbQFss-E25Xx0dxj0ZN_8Rm2Q_9ByAkvWOpX861xArvW7VlMGyt6gpD3wmX9CZ6HszXT7RudVy3nbjgHDUiH4DSaAuFvVKYCZI_fxM-l2qVz53hXQ2EJ8rX566GhGavCdG7jg6ulckVGr0O9kC9mUG63iXMUqfwm6IOawkmTSMTx0MZMc"/>
                        <div className="absolute inset-0 flex items-center justify-center">
                            <div className="relative w-full h-full">
                            <div className="absolute top-1/4 left-1/3 w-2 h-2 bg-error rounded-full animate-pulse"></div>
                            <div className="absolute top-1/2 left-2/3 w-2 h-2 bg-error rounded-full animate-pulse"></div>
                            <div className="absolute bottom-1/4 right-1/4 w-2 h-2 bg-primary rounded-full animate-pulse" style={{ animationDelay: '1s'}}></div>
                            </div>
                        </div>
                    </div>
                    <div className="mt-4 flex justify-between items-center text-[10px] font-mono">
                        <span className="text-slate-500">PRIMARY NODE: VA-US-1</span>
                        <span className="text-emerald-500">ACTIVE</span>
                    </div>
                </div>
            </div>
            
            <div className="mt-8 lg:w-2/3 bg-surface-container-lowest p-6 rounded-lg border border-outline-variant/10 font-mono text-[11px]">
                <div className="flex justify-between mb-4 border-b border-outline-variant/20 pb-2">
                    <span className="text-slate-500">EVENT_REPORTING_DAEMON</span>
                    <span className="text-primary-dim">Automated Scheduler</span>
                </div>
                <div className="space-y-1">
                    <div className="flex gap-4"><span className="text-slate-600">14:23:01</span> <span className="text-emerald-400">[OK]</span> <span className="text-slate-300">Auth success: admin@local.sys</span></div>
                    <div className="flex gap-4"><span className="text-slate-600">14:23:12</span> <span className="text-yellow-500">[WRN]</span> <span className="text-slate-300">Anomaly detected: Segment 0xF24 Access violation</span></div>
                    <div className="flex gap-4"><span className="text-slate-600">14:23:45</span> <span className="text-error">[CRT]</span> <span className="text-slate-300">Inbound connection dropped from CN:120.2.x.x</span></div>
                    <div className="flex gap-4"><span className="text-slate-600">14:23:46</span> <span className="text-primary">[INF]</span> <span className="text-slate-300">Weekly executive compilation queued...</span></div>
                </div>
            </div>
        </main>
      </>
  )
}
