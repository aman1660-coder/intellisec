import EmptyState from "../components/EmptyState";
import { useScans } from "../hooks/useScans";

export default function ScanComparison() {
  const { scans, loading } = useScans();
  if (loading) return <p className="text-slate-400">Loading comparison...</p>;
  if (scans.length < 2) return <EmptyState title="Need two scans to compare" message="Run at least two scans to observe fixed findings, new findings, score movement, compliance changes, and PQC readiness changes." />;
  const [latest, previous] = scans;
  const latestIds = new Set((latest.findings || []).map((f) => f.finding_type));
  const previousIds = new Set((previous.findings || []).map((f) => f.finding_type));
  const fixed = [...previousIds].filter((id) => !latestIds.has(id));
  const added = [...latestIds].filter((id) => !previousIds.has(id));
  return (
    <div className="space-y-5">
      <div><p className="text-sm uppercase tracking-wide text-slate-500">Scan Comparison</p><h1 className="mt-2 text-3xl font-semibold text-white">Latest versus previous</h1></div>
      <div className="grid gap-4 md:grid-cols-4">
        <div className="panel rounded-lg p-4"><p className="text-sm text-slate-500">Score change</p><p className="mt-2 text-3xl font-semibold text-cyanx">{(latest.intellisec_score || 0) - (previous.intellisec_score || 0)}</p></div>
        <div className="panel rounded-lg p-4"><p className="text-sm text-slate-500">Fixed finding types</p><p className="mt-2 text-3xl font-semibold text-leaf">{fixed.length}</p></div>
        <div className="panel rounded-lg p-4"><p className="text-sm text-slate-500">New finding types</p><p className="mt-2 text-3xl font-semibold text-gold">{added.length}</p></div>
        <div className="panel rounded-lg p-4"><p className="text-sm text-slate-500">PQC change</p><p className="mt-2 text-3xl font-semibold text-white">{((latest.pqc_readiness?.score || 0) - (previous.pqc_readiness?.score || 0)).toFixed(1)}</p></div>
      </div>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="panel rounded-lg p-5"><h2 className="font-semibold text-white">Fixed</h2><pre className="mt-3 text-sm text-slate-300">{fixed.join("\n") || "No fixed finding types detected."}</pre></div>
        <div className="panel rounded-lg p-5"><h2 className="font-semibold text-white">New</h2><pre className="mt-3 text-sm text-slate-300">{added.join("\n") || "No new finding types detected."}</pre></div>
      </div>
    </div>
  );
}

