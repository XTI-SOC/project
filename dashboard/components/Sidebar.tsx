"use client"
import Link from "next/link"
import { usePathname } from "next/navigation"

export function Sidebar() {
  const pathname = usePathname()

  const links = [
    { href: "/", icon: "dashboard", label: "Overview" },
    { href: "/threat-intelligence", icon: "radar", label: "Threat Hunter" },
    { href: "/log-stream", icon: "terminal", label: "Log Stream" },
    { href: "/forensics", icon: "biotech", label: "Forensics" },
    { href: "/reports", icon: "description", label: "Reports" },
  ]

  return (
    <aside className="h-screen w-64 fixed left-0 top-0 bg-[#0d172d] border-r border-blue-500/10 hidden lg:flex flex-col pt-20 z-40">
      <div className="px-6 mb-8">
        <div className="bg-primary/5 rounded-lg p-4 border border-primary/10">
          <div className="flex items-center gap-3 mb-2">
            <span className="material-symbols-outlined text-primary" style={{fontVariationSettings: "'FILL' 1"}}>shield</span>
            <span className="font-headline font-bold text-sm text-on-surface">SYSTEM HEALTH</span>
          </div>
          <div className="w-full bg-surface-container-lowest h-1.5 rounded-full overflow-hidden">
            <div className="bg-primary h-full w-[92%]"></div>
          </div>
          <div className="flex justify-between mt-1">
            <span className="text-[10px] text-slate-500">92% Operational</span>
            <span className="text-[10px] text-slate-500">4ms Latency</span>
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
        <button className="w-full bg-gradient-to-br from-primary to-primary-container text-on-primary py-3 rounded-lg text-[10px] font-bold tracking-widest uppercase hover:opacity-90 transition-opacity">
            GENERATE REPORT
        </button>
        <div className="mt-6 space-y-2 px-2">
          <div className="flex items-center gap-2 text-[10px] text-slate-500">
            <span className="material-symbols-outlined text-sm">potted_plant</span>
            <span>Status: Online</span>
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
