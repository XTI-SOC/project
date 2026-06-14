"use client"
import Link from "next/link"
import { usePathname } from "next/navigation"
import useSWR from "swr"
import { fetchStats, API_BASE } from "@/lib/api"

export function Sidebar() {
  const pathname = usePathname()

  const links = [
    { href: "/", icon: "dashboard", label: "Overview" },
    { href: "/incidents", icon: "warning", label: "Incidents" },
    { href: "/threat-intelligence", icon: "radar", label: "Threat Hunter" },
    { href: "/log-stream", icon: "terminal", label: "Log Stream" },
  ]

  const { data: stats } = useSWR(`${API_BASE}/stats`, fetchStats, { refreshInterval: 5000 })
  const dbSize = stats?.db?.size_mb || 0;
  const isHealthy = dbSize < 1000;
  const healthPercent = isHealthy ? 99 : Math.max(0, 100 - (dbSize / 1000 * 100));

  return (
    <aside className="h-screen w-64 fixed left-0 top-0 bg-[#0d172d] border-r border-blue-500/10 hidden lg:flex flex-col pt-20 z-40">
      <div className="px-6 mb-8">
        <div className="bg-primary/5 rounded-lg p-4 border border-primary/10">
          <div className="flex items-center gap-3 mb-2">
            <span className="material-symbols-outlined text-primary" style={{fontVariationSettings: "'FILL' 1"}}>shield</span>
            <span className="font-headline font-bold text-sm text-on-surface">SYSTEM HEALTH</span>
          </div>
          <div className="w-full bg-surface-container-lowest h-1.5 rounded-full overflow-hidden">
            <div className={`h-full transition-all ${isHealthy ? 'bg-primary' : 'bg-error'}`} style={{width: `${healthPercent}%`}}></div>
          </div>
          <div className="flex justify-between mt-1">
            <span className="text-[10px] text-slate-500">{healthPercent.toFixed(0)}% Operational</span>
            <span className="text-[10px] text-slate-500">Live</span>
          </div>
        </div>
      </div>
      
      <div className="flex-1 space-y-1 px-4">
        {links.map((link) => {
          const isActive = pathname === link.href;
          return (
             <Link key={link.href} href={link.href}>
                <div className={`flex items-center gap-4 px-4 py-3 cursor-pointer transition-all ${isActive ? 'bg-blue-500/10 text-blue-400 border-r-4 border-blue-500 font-bold' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/50'}`}>
                    <span className="material-symbols-outlined text-xl">{link.icon}</span>
                    <span className="text-xs font-medium uppercase tracking-wider">{link.label}</span>
                </div>
            </Link>
          )
        })}
      </div>
      
      <div className="p-4 mt-auto">
        <div className="space-y-2 px-2">
          <div className="flex items-center gap-2 text-[10px] text-slate-500">
            <span className={`material-symbols-outlined text-sm ${stats ? 'text-primary' : 'text-error'}`}>potted_plant</span>
            <span>Status: {stats ? 'Online' : 'Offline'}</span>
          </div>
          <div className="flex items-center gap-2 text-[10px] text-slate-500">
            <span className="material-symbols-outlined text-sm">build</span>
            <span>v2.4.0-Stable</span>
          </div>
        </div>
      </div>
    </aside>
  )
}
