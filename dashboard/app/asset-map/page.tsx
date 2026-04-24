"use client"
import { useEffect, useState } from "react"
import useSWR from "swr"
import { fetchAlerts, fetchStats, API_BASE } from "@/lib/api"
import type { Alert } from "@/lib/api"
import { Header } from "@/components/Header"

export default function AssetMapPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  
  useEffect(() => {
    fetchAlerts(100).then(setAlerts).catch(console.error)
  }, [])
  
  const uniqueSrcIps = new Set(alerts.map(a => a.src_ip));
  const uniqueDstPorts = new Set(alerts.map(a => a.dst_port));

  const stats = {
      endpoints: uniqueSrcIps.size,
      servers: uniqueDstPorts.size,
      critical: alerts.filter(a => a.risk_score >= 80).length,
      iotNodes: Math.floor(uniqueSrcIps.size * 1.5) // Just a mock derived stat for visual completeness
  }

  // Get unique source IPs as active nodes
  const activeNodes = Array.from(new Set(alerts.map(a => a.src_ip))).slice(0, 5)

  return (
    <>
      <Header wsStatus="open" />
      <main className="lg:pl-64 pt-16 h-screen flex flex-col overflow-hidden">
        <div className="flex-1 relative bg-surface-container-low flex overflow-hidden">
        
          <aside className="w-80 h-full bg-surface border-r border-outline-variant/10 flex flex-col z-30 shadow-2xl">
            <div className="p-6 border-b border-outline-variant/10">
                <h3 className="font-headline text-lg font-bold text-on-background flex items-center gap-2">
                    <span className="material-symbols-outlined text-primary">inventory_2</span>
                    Asset Inventory
                </h3>
                <p className="text-on-surface-variant text-xs mt-1">Real-time infrastructure health</p>
            </div>
            
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
                <div className="grid grid-cols-2 gap-3">
                    <div className="bg-surface-container-high p-4 rounded-lg border-l-2 border-primary">
                        <span className="text-[10px] text-on-surface-variant uppercase font-bold tracking-tighter">Endpoints</span>
                        <div className="font-headline text-2xl font-bold text-on-surface">{stats.endpoints}</div>
                    </div>
                    <div className="bg-surface-container-high p-4 rounded-lg border-l-2 border-secondary">
                        <span className="text-[10px] text-on-surface-variant uppercase font-bold tracking-tighter">Servers</span>
                        <div className="font-headline text-2xl font-bold text-on-surface">{stats.servers}</div>
                    </div>
                    <div className="bg-surface-container-high p-4 rounded-lg border-l-2 border-tertiary">
                        <span className="text-[10px] text-on-surface-variant uppercase font-bold tracking-tighter">Critical</span>
                        <div className="font-headline text-2xl font-bold text-error">{stats.critical}</div>
                    </div>
                    <div className="bg-surface-container-high p-4 rounded-lg border-l-2 border-outline">
                        <span className="text-[10px] text-on-surface-variant uppercase font-bold tracking-tighter">IoT Nodes</span>
                        <div className="font-headline text-2xl font-bold text-on-surface">{stats.iotNodes}</div>
                    </div>
                </div>
                
                <div className="mt-6">
                    <h4 className="text-[10px] text-on-surface-variant uppercase font-bold tracking-widest mb-3">Live Feed</h4>
                    <div className="space-y-2">
                        {activeNodes.map((ip, i) => {
                            const isCritical = alerts.find(a => a.src_ip === ip && a.risk_score >= 80)
                            if (isCritical) {
                                return (
                                    <div key={ip} className="group flex items-center justify-between p-3 bg-error-container/10 hover:bg-error-container/20 transition-colors rounded border border-error-container/20">
                                        <div className="flex items-center gap-3">
                                            <div className="w-2 h-2 rounded-full bg-tertiary shadow-[0_0_10px_rgba(255,113,106,0.8)] animate-pulse"></div>
                                            <div>
                                                <div className="text-xs font-mono text-error">{ip}</div>
                                                <div className="text-[10px] text-error/70">Compromised Asset</div>
                                            </div>
                                        </div>
                                        <span className="material-symbols-outlined text-sm text-error">warning</span>
                                    </div>
                                )
                            }
                            return (
                                <div key={ip} className="group flex items-center justify-between p-3 bg-surface-container-lowest/50 hover:bg-primary/5 transition-colors rounded">
                                    <div className="flex items-center gap-3">
                                        <div className="w-2 h-2 rounded-full bg-primary shadow-[0_0_8px_rgba(173,198,255,0.8)]"></div>
                                        <div>
                                            <div className="text-xs font-mono text-on-surface">{ip}</div>
                                            <div className="text-[10px] text-on-surface-variant">Active Connection</div>
                                        </div>
                                    </div>
                                    <span className="material-symbols-outlined text-sm text-on-surface-variant group-hover:text-primary transition-colors cursor-pointer">open_in_new</span>
                                </div>
                            )
                        })}
                    </div>
                </div>
            </div>
          </aside>
          
          <section className="flex-1 relative overflow-hidden bg-[#000d1a]">
            <div className="absolute inset-0 opacity-40 mix-blend-screen pointer-events-none">
                <img className="w-full h-full object-cover grayscale invert contrast-125" src="https://lh3.googleusercontent.com/aida-public/AB6AXuD-O7QCy3utqPoo-JMC9h3J41du8_6au_5DOO8XxSKw25eSSyv62ptyxxfyj1eb4dbZ2HIw3_FJ8-SsY66PUrOzzk3wSoP6yrkSwRj51audGZ6K3sNwdX-VAzXX-r8SXLtvLpoPWL-VWReC5G5mdML9UfHbLB7Zgd-Hr5Ampl2KdllCJZ7cL9IxG_ZJnkULrDvuajT_zhu8B2BkEjTi4UQhLiL21BAVsrPvzoCCTNcTb7BTPrh0JGAkgTmHXDy6uGXpz2TIJ1fs2ZY"/>
            </div>
            <div className="absolute inset-0 bg-gradient-to-t from-surface-container-lowest via-transparent to-surface-container-lowest/30 pointer-events-none"></div>
            
            <div className="absolute bottom-8 left-8 bg-surface-container/80 backdrop-blur-xl p-4 rounded-lg border border-outline-variant/20 shadow-2xl z-20">
                <h5 className="text-[10px] uppercase font-bold tracking-widest text-on-surface-variant mb-3">Map Legend</h5>
                <div className="grid grid-cols-2 gap-x-6 gap-y-2">
                <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-primary ring-2 ring-primary/20"></span>
                <span className="text-[11px] text-on-surface">Healthy</span>
                </div>
                <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-tertiary animate-pulse shadow-[0_0_8px_rgba(255,113,106,0.8)]"></span>
                <span className="text-[11px] text-tertiary">Compromised</span>
                </div>
                </div>
            </div>
          </section>
        </div>
      </main>
    </>
  )
}
