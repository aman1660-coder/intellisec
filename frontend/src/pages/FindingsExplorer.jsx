import EmptyState from "../components/EmptyState";
import SeverityBadge from "../components/SeverityBadge";
import { useScans } from "../hooks/useScans";

export default function FindingsExplorer() {
  const { latest, loading } = useScans();
  if (loading) return <p className="text-slate-400">Loading findings...</p>;
  if (!latest) return <EmptyState title="No findings yet" />;
  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm uppercase tracking-wide text-slate-500">Findings Explorer</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">{latest.normalized_target}</h1>
      </div>
      <div className="grid gap-4">
        {(latest.findings || []).map((finding) => (
          <div key={finding.finding_id} className="panel rounded-lg p-4">
            <div className="flex flex-col justify-between gap-3 md:flex-row md:items-start">
              <div>
                <p className="text-xs uppercase text-slate-500">{finding.finding_type}</p>
                <h2 className="mt-1 text-lg font-semibold text-white">{finding.title}</h2>
                <p className="mt-2 text-sm text-slate-400">{finding.description}</p>
              </div>
              <SeverityBadge severity={finding.severity} />
            </div>
            <p className="mt-4 rounded-md bg-ink/70 p-3 text-sm text-slate-300">{finding.remediation}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

