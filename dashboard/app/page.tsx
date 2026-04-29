"use client"
import { useEffect, useRef, useState } from "react"
import useSWR from "swr"
import { fetchAlerts, fetchStats, WS_URL, API_BASE, API_KEY } from "@/lib/api"
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

    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout;

    const connectWebSocket = () => {
      ws = new WebSocket(WS_URL)
      wsRef.current = ws
      
      ws.onopen = () => {
        setWsStatus("open")
        ws?.send(JSON.stringify({ token: API_KEY }))
      }
      
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
                    {Array.from(new Set(alerts.filter(a => a.cti_data?.country).map(a => a.src_ip)))
                      .slice(0, 10)
                      .map((ip, idx) => {
                       const alert = alerts.find(a => a.src_ip === ip && a.cti_data?.country)!;
                       const COUNTRY_COORDS: Record<string, {top: number, left: number}> = {
                          "US": { top: 38, left: 22 }, "CA": { top: 28, left: 20 },
                          "CN": { top: 42, left: 78 }, "RU": { top: 25, left: 72 },
                          "IN": { top: 52, left: 71 }, "BR": { top: 68, left: 32 },
                          "GB": { top: 32, left: 48 }, "DE": { top: 34, left: 51 },
                          "FR": { top: 37, left: 49 }, "AU": { top: 80, left: 85 },
                          "IR": { top: 45, left: 63 }, "KP": { top: 40, left: 82 },
                          "UA": { top: 35, left: 58 }, "ZA": { top: 78, left: 54 },
                          "JP": { top: 40, left: 86 }, "KR": { top: 42, left: 84 },
                          "IL": { top: 45, left: 58 }, "NL": { top: 33, left: 50 },
                       };
                       const coords = COUNTRY_COORDS[alert.cti_data!.country];
                       if (!coords) return null; // Hide dot if country not mapped
                       
                       const isCritical = alert.risk_score >= 80;
                       return (
                          <div key={ip} 
                               className={`absolute w-2 h-2 rounded-full pulse-red ${isCritical ? 'bg-error' : 'bg-primary'}`} 
                               style={{top: `${coords.top}%`, left: `${coords.left}%`, animationDelay: `${idx * 0.5}s`}}
                               title={`${alert.src_ip} (${alert.cti_data!.country})`}>
                          </div>
                       )
                    })}
                  </div>
                  </div>
                </div>
                <div className="mt-4 flex justify-between items-center text-[10px] font-mono">
                  <span className="text-slate-500">ACTIVE NODES: {Array.from(new Set(alerts.map(a => a.src_ip))).length}</span>
                  <span className="text-emerald-500">REAL-TIME</span>
                </div>
              </div>

              <div className="bg-surface-container-lowest p-4 flex-1 rounded-lg border border-outline-variant/10 font-mono text-[11px] overflow-hidden">
                  <div className="flex justify-between mb-4 border-b border-outline-variant/20 pb-2">
                  <span className="text-slate-500">REALTIME_EVENT_BUS_LOG</span>
                  <span className="text-primary-dim">SESSION: SOC_ANALYST_01</span>
                  </div>
                  <div className="space-y-1">
                    {alerts.slice(0, 6).map((alert) => {
                      const timeString = new Date(alert.timestamp * 1000).toLocaleTimeString([], { hour12: false });
                      let levelObj = { tag: "[INF]", color: "text-primary" };
                      if (alert.risk_score > 80) levelObj = { tag: "[CRT]", color: "text-error" };
                      else if (alert.risk_score > 50) levelObj = { tag: "[WRN]", color: "text-yellow-500" };
                      else if (alert.ml_class === "BENIGN") levelObj = { tag: "[OK]", color: "text-emerald-400" };

                      return (
                        <div key={`log-${alert.alert_id}`} className="flex gap-4">
                          <span className="text-slate-600 whitespace-nowrap">{timeString}</span>
                          <span className={levelObj.color}>{levelObj.tag}</span>
                          <span className="text-slate-300 truncate">
                            {alert.attack_type !== "UNKNOWN" && alert.attack_type !== "BENIGN" ? alert.attack_type : alert.ml_class} from {alert.src_ip}:{alert.src_port}
                          </span>
                        </div>
                      )
                    })}
                    {alerts.length === 0 && (
                      <div className="text-slate-500 italic">Waiting for events...</div>
                    )}
                </div>
              </div>
          </div>
        </div>
      </main>
    </>
  )
}
