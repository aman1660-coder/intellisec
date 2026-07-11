import { AlertTriangle, Binary, ClipboardCheck, GitBranch, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import EmptyState from "../components/EmptyState";
import MetricCard from "../components/MetricCard";
import SeverityBadge from "../components/SeverityBadge";
import { SeverityPie, TrendLine } from "../charts/RiskCharts";
import { useScans } from "../hooks/useScans";
import { dateShort } from "../utils/format";

export default function Dashboard() {
  const { scans, latest, loading, error } = useScans();
  if (loading) return <p className="text-slate-400">Loading dashboard...</p>;
  if (error) return <p className="rounded-md border border-danger/30 bg-danger/10 p-3 text-rose-100">{error}</p>;
  if (!scans.length) return <EmptyState />;
  const allFindings = scans.flatMap((scan) => scan.findings || []);
  const activePaths = scans.reduce((sum, scan) => sum + (scan.attack_paths?.length || 0), 0);
  const complianceCount = scans.reduce((sum, scan) => sum + (scan.compliance_mappings?.length || 0), 0);
  const pqcAverage = scans.reduce((sum, scan) => sum + (scan.pqc_readiness?.score || 0), 0) / scans.length;
  return (
    <div className="space-y-6">
      <div className="flex flex-col justify-between gap-4 md:flex-row md:items-end">
        <div>
          <p className="text-sm uppercase tracking-wide text-slate-500">Security Posture Dashboard</p>
          <h1 className="mt-2 text-3xl font-semibold text-white">Current posture</h1>
        </div>
        <Link to="/app/new-scan" className="btn-primary">Run authorized scan</Link>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <MetricCard icon={ShieldCheck} label="IntelliSec Score" value={latest.intellisec_score || 0} detail="latest scan" />
        <MetricCard icon={AlertTriangle} label="Findings" value={allFindings.length} detail={`${allFindings.filter((f) => f.severity === "high").length} high`} tone="amber" />
        <MetricCard icon={GitBranch} label="Attack Paths" value={activePaths} detail="active chains" tone="rose" />
        <MetricCard icon={ClipboardCheck} label="Compliance Coverage" value={complianceCount} detail="mapped controls" tone="green" />
        <MetricCard icon={Binary} label="PQC Readiness" value={`${pqcAverage.toFixed(1)}/10`} detail="average score" tone="blue" />
      </div>
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="panel rounded-lg p-5">
          <h2 className="text-lg font-semibold text-white">Security Posture Trend</h2>
          <TrendLine scans={scans} />
        </div>
        <div className="panel rounded-lg p-5">
          <h2 className="text-lg font-semibold text-white">Risk Distribution</h2>
          <SeverityPie findings={allFindings} />
        </div>
      </div>
      <div className="panel rounded-lg p-5">
        <h2 className="text-lg font-semibold text-white">Latest Scans</h2>
        <div className="mt-4 divide-y divide-line">
          {scans.slice(0, 6).map((scan) => (
            <Link key={scan.id} to={`/app/scans/${scan.id}`} className="flex flex-col gap-2 py-3 hover:bg-white/[0.02] md:flex-row md:items-center md:justify-between">
              <div>
                <p className="font-medium text-white">{scan.normalized_target}</p>
                <p className="text-xs text-slate-500">{dateShort(scan.timestamp)} - {scan.scan_mode}</p>
              </div>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={scan.risk_assessment?.severity} />
                <span className="text-sm font-semibold text-cyanx">{scan.intellisec_score}/100</span>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}

