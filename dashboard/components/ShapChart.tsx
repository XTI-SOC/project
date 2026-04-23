"use client"
import { useEffect, useRef } from "react"
import type { ShapFeature } from "@/lib/api"
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts"

export function ShapChart({ data, alertColor }: { data: ShapFeature[], alertColor?: string }) {
  const sorted = [...data]
    .sort((a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value))
    .slice(0, 5) // Display top 5

  return (
    <div className="h-40 w-full bg-[#031d4b]/30 p-2 rounded border border-[#2b4680]/30 shadow-inner">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          layout="vertical"
          data={sorted}
          margin={{ top: 5, right: 10, left: 10, bottom: 5 }}
        >
          <XAxis type="number" hide domain={["dataMin", "dataMax"]} />
          <YAxis
            type="category"
            dataKey="feature"
            axisLine={false}
            tickLine={false}
            tick={{ fill: "#91aaeb", fontSize: 11, fontFamily: "monospace" }}
            width={120}
          />
          <Tooltip
            cursor={{ fill: "rgba(173,198,255,0.02)" }}
            contentStyle={{
              backgroundColor: "#05183c",
              border: "1px solid rgba(43, 70, 128, 0.5)",
              borderRadius: "2px",
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              color: "#dee5ff",
            }}
            formatter={(value: any) => [Number(value).toFixed(4), "SHAP_VAL"]}
          />
          <Bar dataKey="shap_value" radius={[0, 2, 2, 0]} barSize={10}>
            {sorted.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={entry.shap_value > 0 ? "#ff716a" : "#adc6ff"}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
