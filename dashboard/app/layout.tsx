import type { Metadata } from "next"
import { Space_Grotesk, Inter, JetBrains_Mono } from "next/font/google"
import "./globals.css"
import { Sidebar } from "@/components/Sidebar"

const spaceGrotesk = Space_Grotesk({ subsets: ["latin"], weight: ["300", "400", "500", "600", "700"] })
const inter = Inter({ subsets: ["latin"], weight: ["300", "400", "500", "600", "700"] })
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["400", "500"] })

export const metadata: Metadata = {
  title: "XTI-SOC Dashboard",
  description: "Explainable Threat Intelligence SOC",
}

export default function RootLayout({
  children,
}: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet" />
        <style>{`.material-symbols-outlined { font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24; }`}</style>
      </head>
      <body className={`bg-surface text-on-surface selection:bg-primary-container selection:text-on-primary-container min-h-screen`}>
        <Sidebar />
        {children}
        <nav className="md:hidden fixed bottom-0 left-0 right-0 h-16 bg-[#0d172d] flex items-center justify-around border-t border-blue-500/10 z-50">
            <div className="flex flex-col items-center text-blue-500">
                <span className="material-symbols-outlined" style={{ fontVariationSettings: "'FILL' 1" }}>dashboard</span>
                <span className="text-[9px] mt-1 font-bold">DASHBOARD</span>
            </div>
            <div className="flex flex-col items-center text-slate-500">
                <span className="material-symbols-outlined">radar</span>
                <span className="text-[9px] mt-1">HUNT</span>
            </div>
            <div className="flex flex-col items-center text-slate-500">
                <span className="material-symbols-outlined">terminal</span>
                <span className="text-[9px] mt-1">LOGS</span>
            </div>
            <div className="flex flex-col items-center text-slate-500">
                <span className="material-symbols-outlined">settings</span>
                <span className="text-[9px] mt-1">SYSTEM</span>
            </div>
        </nav>
      </body>
    </html>
  )
}
