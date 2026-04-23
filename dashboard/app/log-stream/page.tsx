"use client"
import { useEffect, useState, useRef } from "react"
import { fetchAlerts, WS_URL } from "@/lib/api"
import type { Alert } from "@/lib/api"
import { Header } from "@/components/Header"

export default function LogStreamPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [logs, setLogs] = useState<{ id: string, text: string, type: string, time: string }[]>([])
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetchAlerts(50).then(setAlerts).catch(console.error)

    const ws = new WebSocket(WS_URL)
    ws.onmessage = (e) => {
      const incoming: Alert = JSON.parse(e.data)
      setAlerts(prev => [incoming, ...prev].slice(0, 100))
    }
    return () => ws.close()
  }, [])

  // Map alerts to terminal logs
  useEffect(() => {
     const mapped = alerts.map(a => {
         let type = "primary-dim"
         let header = "TCP_SYN"
         if (a.risk_score >= 80) {
             type = "error"
             header = "FLOOD_DETECT"
         } else if (a.risk_score >= 40) {
             type = "tertiary"
             header = "SCAN_DETECT"
         } else if (a.attack_type === "BENIGN") {
             type = "secondary-dim"
             header = "ICMP_ECHO"
         }

         return {
             id: a.alert_id,
             time: new Date(a.timestamp).toISOString(),
             type,
             text: `[${header}] ${a.src_ip}:${a.src_port} -> ${a.dst_ip}:${a.dst_port} [RISK: ${a.risk_score.toFixed(1)}] ${a.attack_type !== "BENIGN" ? "("+a.attack_type+")" : ""}`
         }
     })
     setLogs(mapped)
  }, [alerts])

  return (
    <>
      <Header wsStatus="open" />
      <main className="md:pl-64 pt-16 flex-1 h-screen flex flex-col overflow-hidden bg-[#060e20]">
        <section className="m-6 flex flex-col gap-2">
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-primary text-xl">segment</span>
                    <h2 className="font-headline font-bold text-2xl tracking-tight uppercase text-on-surface">LOG STREAM</h2>
                </div>
                <div className="flex items-center gap-2 bg-error-container/20 px-3 py-1 rounded-sm">
                    <span className="w-2 h-2 rounded-full bg-error animate-pulse"></span>
                    <span className="font-mono text-[10px] font-bold text-error uppercase tracking-widest">LIVE</span>
                </div>
            </div>
            <div className="grid grid-cols-3 gap-2 mt-2">
                <div className="bg-surface-container-low p-2 rounded-sm border border-outline-variant/10">
                    <p className="text-[10px] text-on-surface-variant font-label uppercase">PPS</p>
                    <p className="font-headline text-lg font-medium text-primary">14.2K</p>
                </div>
                <div className="bg-surface-container-low p-2 rounded-sm border border-outline-variant/10">
                    <p className="text-[10px] text-on-surface-variant font-label uppercase">FLOWS</p>
                    <p className="font-headline text-lg font-medium text-tertiary">{alerts.length}</p>
                </div>
                <div className="bg-surface-container-low p-2 rounded-sm border border-outline-variant/10">
                    <p className="text-[10px] text-on-surface-variant font-label uppercase">UPTIME</p>
                    <p className="font-headline text-lg font-medium text-secondary">04:12:09</p>
                </div>
            </div>
        </section>

        <div className="flex-1 mx-6 mb-6 bg-surface-container-lowest rounded-lg overflow-hidden relative border border-outline-variant/10 shadow-2xl flex flex-col">
            <div className="absolute inset-0 scanline opacity-30 bg-gradient-to-t from-transparent via-primary/5 to-transparent pointer-events-none"></div>
            
            <div className="bg-surface-container-high px-4 py-2 flex items-center justify-between border-b border-outline-variant/20 z-10">
                <div className="flex items-center gap-4">
                    <div className="flex gap-1.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-error/40"></div>
                        <div className="w-2.5 h-2.5 rounded-full bg-tertiary/40"></div>
                        <div className="w-2.5 h-2.5 rounded-full bg-primary/40"></div>
                    </div>
                    <span className="font-mono text-[11px] text-on-surface-variant uppercase tracking-tighter">nfstream_worker_01@xti-soc:~/logs</span>
                </div>
                <span className="material-symbols-outlined text-on-surface-variant text-sm">settings_ethernet</span>
            </div>

            <div ref={scrollRef} className="flex-1 p-4 overflow-y-auto font-mono text-[11px] leading-relaxed select-none z-10" style={{scrollbarWidth: "thin", scrollbarColor: "#004395 #000000"}}>
                <div className="space-y-1 pb-10">
                    <p className="text-secondary opacity-50">[INIT] Attaching to interface eth0... SUCCESS</p>
                    <p className="text-secondary opacity-50">[INIT] Kernel hook loaded at 0xffffffff81001000</p>
                    {logs.map((log) => (
                         <p key={log.id} className={`text-${log.type}`}>
                             <span className="text-on-surface-variant">{log.time}</span>{" "}
                             {log.text}
                         </p>
                    ))}
                    <div className="flex items-center gap-2 mt-4">
                        <span className="w-1 h-4 bg-primary animate-pulse"></span>
                        <span className="text-primary font-bold">_</span>
                    </div>
                </div>
            </div>

            <div className="bg-surface-container-high/80 backdrop-blur-sm px-4 py-1.5 flex items-center justify-between border-t border-outline-variant/20 z-10">
                <div className="flex items-center gap-3">
                    <span className="font-mono text-[9px] text-primary uppercase">Packets: 4,521,092</span>
                    <span className="font-mono text-[9px] text-tertiary uppercase">Dropped: 0.02%</span>
                </div>
                <div className="flex flex-1 items-center justify-end gap-1">
                    <span className="font-mono text-[9px] text-secondary uppercase">Buffer: 4%</span>
                </div>
            </div>
        </div>
      </main>
    </>
  )
}
