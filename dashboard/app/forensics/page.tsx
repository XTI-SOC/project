"use client"
import { useEffect, useState } from "react"
import { fetchAlerts } from "@/lib/api"
import type { Alert } from "@/lib/api"
import { Header } from "@/components/Header"

export default function ForensicsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  
  useEffect(() => {
    fetchAlerts(50).then(setAlerts).catch(console.error)
  }, [])

  return (
    <>
      <Header wsStatus="open" />
      <main className="md:pl-64 pt-20 p-6 min-h-screen">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6 max-w-screen-2xl mx-auto">
          
          <section className="md:col-span-8 bg-surface-container-low rounded-xl overflow-hidden relative border border-outline-variant/10 min-h-[500px]">
            <div className="absolute top-4 left-4 z-10">
                <h3 className="font-headline text-lg font-bold text-primary tracking-tight">Investigative Canvas</h3>
                <p className="text-xs text-on-surface-variant font-mono uppercase tracking-widest">Active_Cluster_Graph_0x44</p>
            </div>
            
            <div className="w-full h-full flex items-center justify-center p-12">
                <svg className="w-full h-full opacity-80" viewBox="0 0 800 500">
                    <defs>
                        <radialGradient cx="50%" cy="50%" fx="50%" fy="50%" id="nodeGlow" r="50%">
                            <stop offset="0%" style={{stopColor: "#adc6ff", stopOpacity: 0.4}}></stop>
                            <stop offset="100%" style={{stopColor: "#adc6ff", stopOpacity: 0}}></stop>
                        </radialGradient>
                    </defs>
                    <path d="M400 250 L200 150" stroke="#5b74b1" strokeDasharray="4,4" strokeWidth="1"></path>
                    <path d="M400 250 L600 150" stroke="#5b74b1" strokeWidth="1"></path>
                    <path d="M400 250 L400 400" stroke="#ff716a" strokeWidth="2"></path>
                    <path d="M200 150 L100 250" stroke="#5b74b1" strokeWidth="1"></path>

                    <circle cx="400" cy="250" fill="#adc6ff" r="12"></circle>
                    <circle cx="400" cy="250" fill="url(#nodeGlow)" r="24"></circle>
                    <circle cx="200" cy="150" fill="#5b74b1" r="8"></circle>
                    <circle cx="600" cy="150" fill="#5b74b1" r="8"></circle>
                    <circle cx="400" cy="400" fill="#ff716a" r="10"></circle>
                    <circle cx="100" cy="250" fill="#5b74b1" r="6"></circle>

                    <text fill="#adc6ff" fontFamily="JetBrains Mono" fontSize="12" x="420" y="255">CORE_ROUTER</text>
                    <text fill="#91aaeb" fontFamily="JetBrains Mono" fontSize="10" x="140" y="140">ENDPOINT_B2</text>
                    <text fill="#ff716a" fontFamily="JetBrains Mono" fontSize="12" fontWeight="bold" x="420" y="410">MALICIOUS_IP</text>
                </svg>
            </div>
            
            <div className="absolute bottom-0 w-full bg-surface-container-highest/80 backdrop-blur-sm px-6 py-2 flex justify-between items-center text-[10px] font-mono border-t border-outline-variant/10">
                <span className="text-on-surface-variant">NODES: 128 | EDGES: 412</span>
                <span className="text-primary">COORDINATES: 42.12, -71.05</span>
            </div>
          </section>
          
          <section className="md:col-span-4 bg-surface-container rounded-xl border border-outline-variant/10 p-6 flex flex-col items-center">
             <div className="w-full mb-6">
                <h3 className="font-headline text-sm font-bold text-secondary uppercase tracking-[0.2em]">Traffic Flow</h3>
                <p className="text-[10px] text-on-surface-variant font-mono">VECTOR_ANALYSIS_RDR</p>
            </div>
            
            <div className="relative w-48 h-48 flex items-center justify-center">
                <div className="absolute inset-0 border border-outline-variant/20 rounded-full"></div>
                <div className="absolute inset-4 border border-outline-variant/20 rounded-full"></div>
                <div className="absolute inset-10 border border-outline-variant/20 rounded-full"></div>
                
                <div className="absolute w-full h-px bg-outline-variant/20"></div>
                <div className="absolute h-full w-px bg-outline-variant/20"></div>
                
                <svg className="w-full h-full rotate-45" viewBox="0 0 100 100">
                    <polygon fill="rgba(173, 198, 255, 0.2)" points="50,10 80,40 60,90 20,70 15,30" stroke="#adc6ff" strokeWidth="1"></polygon>
                </svg>
                <div className="absolute top-1/2 left-1/2 w-1/2 h-1/2 bg-gradient-to-tr from-primary/20 to-transparent origin-bottom-left rotate-12"></div>
            </div>
            
            <div className="w-full mt-8 grid grid-cols-2 gap-4">
                <div className="bg-surface-container-low p-2 rounded">
                    <div className="text-[9px] text-slate-500 uppercase">Incoming</div>
                    <div className="text-sm font-mono text-primary font-bold">1.2 GB/s</div>
                </div>
                <div className="bg-surface-container-low p-2 rounded">
                    <div className="text-[9px] text-slate-500 uppercase">Outgoing</div>
                    <div className="text-sm font-mono text-tertiary font-bold">842 MB/s</div>
                </div>
            </div>
          </section>
          
          <section className="md:col-span-12 lg:col-span-12 bg-surface-container-low rounded-xl border border-outline-variant/10 overflow-hidden flex flex-col">
            <div className="p-6 border-b border-outline-variant/10 flex justify-between items-center">
                <h3 className="font-headline text-lg font-bold text-primary">Forensic PCAP Streams</h3>
            </div>
            <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="bg-surface-container-lowest text-[10px] uppercase tracking-widest text-slate-500 font-bold">
                            <th className="px-6 py-4">Timestamp</th>
                            <th className="px-6 py-4">Source_IP</th>
                            <th className="px-6 py-4">Dest_IP</th>
                            <th className="px-6 py-4">Alert Type</th>
                            <th className="px-6 py-4 text-right">Risk</th>
                        </tr>
                    </thead>
                    <tbody className="font-mono text-xs divide-y divide-outline-variant/5">
                        {alerts.slice(0, 10).map((a, i) => (
                            <tr key={i} className="hover:bg-primary-dim/10 transition-colors cursor-pointer">
                                <td className="px-6 py-4 text-on-surface-variant">{new Date(a.timestamp).toISOString()}</td>
                                <td className="px-6 py-4 text-primary">{a.src_ip}:{a.src_port}</td>
                                <td className="px-6 py-4 text-on-surface">{a.dst_ip}:{a.dst_port}</td>
                                <td className="px-6 py-4">
                                    <span className="bg-secondary-container text-secondary px-2 py-0.5 rounded-sm">{a.attack_type === "BENIGN" ? "BENIGN" : a.attack_type}</span>
                                </td>
                                <td className="px-6 py-4 text-right text-tertiary font-bold">{a.risk_score.toFixed(1)}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
          </section>
        </div>
      </main>
    </>
  )
}
