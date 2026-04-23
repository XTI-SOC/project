"use client"
import { useEffect, useRef, useState } from "react"
import useSWR from "swr"
import { fetchAlerts, fetchStats, WS_URL, API_BASE } from "@/lib/api"
import type { Alert } from "@/lib/api"
import { StatsRow }   from "@/components/StatsRow"
import { AlertFeed }  from "@/components/AlertFeed"
import { Header }     from "@/components/Header"

export default function Page() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [wsStatus, setWsStatus] = useState<"connecting"|"open"|"closed">("connecting")
  const wsRef = useRef<WebSocket | null>(null)

  const { data: stats } = useSWR(
    `${API_BASE}/stats`,
    (url: string) => fetchStats(url),
    { refreshInterval: 5000 }
  )

  useEffect(() => {
    fetchAlerts(100).then(setAlerts).catch(console.error)

    const ws = new WebSocket(WS_URL)
    wsRef.current = ws
    ws.onopen    = () => setWsStatus("open")
    ws.onclose   = () => setWsStatus("closed")
    ws.onerror   = () => setWsStatus("closed")
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

    return () => ws.close()
  }, [])

  return (
    <>
      <Header wsStatus={wsStatus} />
      <main className="lg:ml-64 pt-20 p-6 min-h-screen pb-20 md:pb-6">
        <StatsRow stats={stats || null} />
        
        {/* Main Content Canvas Grid */}
        <div className="flex flex-col lg:flex-row gap-8">
           <AlertFeed alerts={alerts} />
           
           {/* Terminal View (Bento Grid Style Extra) */}
          <div className="lg:w-1/3 flex flex-col gap-4">
             <div className="bg-surface-container p-4 rounded-lg border border-outline-variant/10 flex flex-col mb-4">
                <h3 className="font-headline font-bold text-xs uppercase tracking-widest mb-4">GLOBAL THREAT MAP</h3>
                <div className="flex-1 relative bg-[#060e20] rounded-sm overflow-hidden min-h-[150px]">
                  <img alt="Dark world map showing glowing cyber attack lines" className="absolute inset-0 w-full h-full object-cover opacity-40 grayscale" src="https://lh3.googleusercontent.com/aida-public/AB6AXuAH3IxlESgGieYS1Pn-E7I0lFdithKa2GVnet9I6dt3mx1wE2E6uYjwKpaOF-2mdNQ8NS2tT5Oscy8PNdbB3Vq2pEBfDdjbQFss-E25Xx0dxj0ZN_8Rm2Q_9ByAkvWOpX861xArvW7VlMGyt6gpD3wmX9CZ6HszXT7RudVy3nbjgHDUiH4DSaAuFvVKYCZI_fxM-l2qVz53hXQ2EJ8rX566GhGavCdG7jg6ulckVGr0O9kC9mUG63iXMUqfwm6IOawkmTSMTx0MZMc"/>
                  <div className="absolute inset-0 flex items-center justify-center">
                  <div className="relative w-full h-full">
                    <div className="absolute top-1/4 left-1/3 w-2 h-2 bg-error rounded-full pulse-red"></div>
                    <div className="absolute top-1/2 left-2/3 w-2 h-2 bg-error rounded-full pulse-red"></div>
                    <div className="absolute bottom-1/4 right-1/4 w-2 h-2 bg-primary rounded-full pulse-red" style={{animationDelay: "1s"}}></div>
                  </div>
                  </div>
                </div>
                <div className="mt-4 flex justify-between items-center text-[10px] font-mono">
                  <span className="text-slate-500">PRIMARY NODE: VA-US-1</span>
                  <span className="text-emerald-500">ACTIVE</span>
                </div>
              </div>

              <div className="bg-surface-container-lowest p-4 flex-1 rounded-lg border border-outline-variant/10 font-mono text-[11px]">
                  <div className="flex justify-between mb-4 border-b border-outline-variant/20 pb-2">
                  <span className="text-slate-500">REALTIME_EVENT_BUS_LOG</span>
                  <span className="text-primary-dim">SESSION: SOC_ANALYST_01</span>
                  </div>
                  <div className="space-y-1">
                  <div className="flex gap-4"><span className="text-slate-600">14:23:01</span> <span className="text-emerald-400">[OK]</span> <span className="text-slate-300">Auth success: admin@local.sys</span></div>
                  <div className="flex gap-4"><span className="text-slate-600">14:23:12</span> <span className="text-yellow-500">[WRN]</span> <span className="text-slate-300">Anomaly detected: Segment 0xF24 Access violation</span></div>
                  <div className="flex gap-4"><span className="text-slate-600">14:23:45</span> <span className="text-error">[CRT]</span> <span className="text-slate-300">Inbound connection dropped from CN:120.2.x.x</span></div>
                  <div className="flex gap-4"><span className="text-slate-600">14:23:46</span> <span className="text-primary">[INF]</span> <span className="text-slate-300">Auto-enrichment started for ID: #9822-AX</span></div>
                </div>
              </div>
          </div>
        </div>
      </main>
    </>
  )
}
