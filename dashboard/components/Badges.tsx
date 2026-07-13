"use client"

const ALERT_TYPE_STYLES: Record<string, string> = {
  ML_CTI:   "bg-[#7f2927] text-[#ff9993] shadow-[0_0_8px_rgba(127,41,39,0.5)]",
  ML_ONLY:  "bg-[#f97316]/20 text-[#f97316] shadow-[0_0_8px_rgba(249,115,22,0.2)]",
  CTI_ONLY: "bg-[#2e3c50] text-[#909fb6]",
  NO_ALERT: "bg-[#06122d] text-[#4d556b]",
}

const ATTACK_TYPE_STYLES: Record<string, string> = {
  DoS:          "bg-[#490106] text-[#ff9993] border border-[#7f2927]",
  DDoS:         "bg-[#3b0003] text-[#fd4e4d] border border-[#ff716a]/30",
  BruteForce:   "bg-[#00225a] text-[#adc6ff] border border-[#004395]",
  WebAttack:    "bg-[#eab308]/10 text-[#facc15] border border-[#eab308]/30",
  Botnet:       "bg-[#22c55e]/10 text-[#4ade80] border border-[#22c55e]/30",
  Infiltration: "bg-[#05183c] text-[#bdd0ff] border border-[#2b4680]",
  UNKNOWN:      "bg-[#06122d] text-[#91aaeb] border border-[#2b4680]/50",
  BENIGN:       "bg-[#2e3c50] text-[#909fb6] border border-[#4d556b]/50",
}

function Badge({ label, className }: { label: string; className: string }) {
  return (
    <span className={`px-2 py-0.5 rounded-[2px] text-[10px] font-sans font-bold uppercase tracking-widest ${className}`}>
      {label}
    </span>
  )
}

export function AlertTypeBadge({ type }: { type: string }) {
  return (
    <Badge
      label={type.replace("_", " + ")}
      className={ALERT_TYPE_STYLES[type] ?? "bg-[#06122d] text-[#91aaeb]"}
    />
  )
}

export function AttackTypeBadge({ type }: { type: string }) {
  return (
    <Badge
      label={type === "BENIGN" ? "BENIGN / TEST" : type}
      className={ATTACK_TYPE_STYLES[type] ?? "bg-[#06122d] text-[#91aaeb] border border-[#2b4680]/50"}
    />
  )
}
