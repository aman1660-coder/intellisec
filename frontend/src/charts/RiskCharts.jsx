import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, PolarAngleAxis, PolarGrid, PolarRadiusAxis, Radar, RadarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { countsBy } from "../utils/format";

const COLORS = {
  critical: "#fb7185",
  high: "#fb923c",
  medium: "#f5c451",
  low: "#20d6c7",
  info: "#94a3b8"
};

export function SeverityPie({ findings = [] }) {
  const counts = countsBy(findings, "severity");
  const data = Object.entries(counts).map(([name, value]) => ({ name, value }));
  if (!data.length) return <p className="p-6 text-sm text-slate-500">No findings to chart.</p>;
  return (
    <ResponsiveContainer width="100%" height={230}>
      <PieChart>
        <Pie data={data} innerRadius={58} outerRadius={86} dataKey="value" nameKey="name" paddingAngle={2}>
          {data.map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name] || COLORS.info} />
          ))}
        </Pie>
        <Tooltip contentStyle={{ background: "#0d1726", border: "1px solid #1f3148" }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function RiskRadar({ risk }) {
  const data = Object.entries(risk?.dimensions || {}).map(([name, item]) => ({ dimension: name.replace("D", "D ").split("_").slice(0, 2).join(" "), score: item.score }));
  if (!data.length) return <p className="p-6 text-sm text-slate-500">Risk dimensions unavailable.</p>;
  return (
    <ResponsiveContainer width="100%" height={280}>
      <RadarChart data={data}>
        <PolarGrid stroke="#1f3148" />
        <PolarAngleAxis dataKey="dimension" tick={{ fill: "#cbd5e1", fontSize: 11 }} />
        <PolarRadiusAxis angle={90} domain={[0, 2]} tick={{ fill: "#64748b", fontSize: 10 }} />
        <Radar dataKey="score" stroke="#20d6c7" fill="#20d6c7" fillOpacity={0.28} />
        <Tooltip contentStyle={{ background: "#0d1726", border: "1px solid #1f3148" }} />
      </RadarChart>
    </ResponsiveContainer>
  );
}

export function TrendLine({ scans = [] }) {
  const data = scans
    .slice()
    .reverse()
    .map((scan, index) => ({ name: `S${index + 1}`, score: scan.intellisec_score || 0, pqc: scan.pqc_readiness?.score || 0 }));
  return (
    <ResponsiveContainer width="100%" height={240}>
      <LineChart data={data}>
        <CartesianGrid stroke="#1f3148" strokeDasharray="3 3" />
        <XAxis dataKey="name" tick={{ fill: "#94a3b8" }} />
        <YAxis tick={{ fill: "#94a3b8" }} />
        <Tooltip contentStyle={{ background: "#0d1726", border: "1px solid #1f3148" }} />
        <Line type="monotone" dataKey="score" stroke="#20d6c7" strokeWidth={2} dot={false} />
        <Line type="monotone" dataKey="pqc" stroke="#f5c451" strokeWidth={2} dot={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}

export function ComplianceBars({ mappings = [] }) {
  const counts = countsBy(mappings, "framework");
  const data = Object.entries(counts).map(([name, value]) => ({ name, value }));
  return (
    <ResponsiveContainer width="100%" height={230}>
      <BarChart data={data}>
        <CartesianGrid stroke="#1f3148" strokeDasharray="3 3" />
        <XAxis dataKey="name" tick={{ fill: "#94a3b8" }} />
        <YAxis tick={{ fill: "#94a3b8" }} />
        <Tooltip contentStyle={{ background: "#0d1726", border: "1px solid #1f3148" }} />
        <Bar dataKey="value" fill="#6ee7a8" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

