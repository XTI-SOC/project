"use client"
import { useEffect, useState } from "react"
import { Shield } from "lucide-react"
import Link from "next/link"
import { usePathname } from "next/navigation"

export function Header({ wsStatus }: { wsStatus: string }) {
  const [time, setTime] = useState("")
  const pathname = usePathname()
  
  useEffect(() => {
    const tick = () => setTime(new Date().toLocaleTimeString())
    tick()
    const timer = setInterval(tick, 1000)
    return () => clearInterval(timer)
  }, [])

  return (
    <header className="fixed top-0 w-full z-50 bg-[#0d172d] border-none shadow-[0_8px_32px_rgba(6,14,32,0.8)] flex justify-between items-center px-6 h-16 max-w-full">
      <div className="flex items-center gap-4">
        <span className="material-symbols-outlined text-blue-500 text-3xl" style={{fontVariationSettings: "'FILL' 1"}}>security</span>
        <div className="flex flex-col leading-tight">
          <span className="text-xl font-bold tracking-tight text-[#dee5ff] font-['Space_Grotesk'] uppercase">XTI-SOC</span>
          <span className="text-[10px] text-slate-400 font-medium tracking-widest hidden md:block">EXPLAINABLE AI INTELLIGENCE</span>
        </div>
      </div>
      
      <nav className="hidden md:flex items-center gap-8 font-['Inter']">
        <Link href="/" className={`text-sm font-medium transition-colors ${pathname === '/' ? 'text-blue-400 border-b-2 border-blue-500 pb-1' : 'text-slate-400 hover:text-slate-200'}`}>Dashboard</Link>
        <Link href="/threat-intelligence" className={`text-sm font-medium transition-colors ${pathname === '/threat-intelligence' ? 'text-blue-400 border-b-2 border-blue-500 pb-1' : 'text-slate-400 hover:text-slate-200'}`}>Threat Intelligence</Link>
        <Link href="/incidents" className={`text-sm font-medium transition-colors ${pathname === '/incidents' ? 'text-blue-400 border-b-2 border-blue-500 pb-1' : 'text-slate-400 hover:text-slate-200'}`}>Incidents</Link>
      </nav>

      <div className="flex items-center gap-6">
        <div className="hidden lg:flex items-center gap-2 bg-surface-container-lowest px-3 py-1 rounded-sm border border-outline-variant/10">
          <div className={`w-2 h-2 rounded-full ${wsStatus === 'open' ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`}></div>
          <span className={`text-[10px] font-mono tracking-tighter ${wsStatus === 'open' ? 'text-emerald-400' : 'text-red-400'}`}>
            {wsStatus === 'open' ? 'LIVE' : 'DISCONNECTED'}
          </span>
          <span className="text-slate-500 mx-1">|</span>
          <span className="text-[11px] font-mono text-on-surface">{time}</span>
        </div>
        
        <div className="flex gap-3">
          <span className="material-symbols-outlined text-slate-400 hover:text-blue-400 cursor-pointer transition-colors">sensors</span>
          <span className="material-symbols-outlined text-slate-400 hover:text-blue-400 cursor-pointer transition-colors">schedule</span>
          <span className="material-symbols-outlined text-slate-400 hover:text-blue-400 cursor-pointer transition-colors">settings</span>
        </div>
        
        <img alt="Analyst profile" className="w-8 h-8 rounded-full border border-blue-500/30 object-cover" src="https://lh3.googleusercontent.com/aida-public/AB6AXuDlibAq7zM6DoZgGZPwRk58hxguut7FK2ja7B_4amN2GkGIZlGNIDC2mM-LSZWfi9Yv38Bv1ME53A2tgdwmqDSzQbBfIPTNL0ExgPbEc38alPVi5SwBy7WS6-OhFeWjS6NceRQQi4w-G8TAlXrrmetziMPWO2StsJLD2jbluLO4VfM-aTCSRH_BqSEqdeI3K4Fvl-dOYGPGFuKH47bYacDF2weZMLZtffcZuAO5FT8JQEALqFYPAcAWezQyTRMGSqmp9wKYUZO6qgY" />
      </div>
    </header>
  )
}
