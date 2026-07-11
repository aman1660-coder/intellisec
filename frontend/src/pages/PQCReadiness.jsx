import EmptyState from "../components/EmptyState";
import { useScans } from "../hooks/useScans";

export default function PQCReadiness() {
  const { latest, loading } = useScans();
  if (loading) return <p className="text-slate-400">Loading PQC readiness...</p>;
  if (!latest) return <EmptyState title="No PQC assessment yet" />;
  const pqc = latest.pqc_readiness || {};
  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm uppercase tracking-wide text-slate-500">PQC Readiness Dashboard</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">{pqc.classification}</h1>
      </div>
      <div className="grid gap-5 lg:grid-cols-[0.7fr_1.3fr]">
        <div className="panel rounded-lg p-6">
          <p className="text-sm text-slate-500">Overall readiness</p>
          <p className="mt-3 text-6xl font-semibold text-gold">{pqc.score}/10</p>
          <p className="mt-3 text-sm text-slate-400">NIST migration target: {pqc.nist_migration_year}. Years remaining: {pqc.years_until_2035}.</p>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          {Object.entries(pqc.dimensions || {}).map(([key, value]) => (
            <div key={key} className="quiet-panel rounded-lg p-4">
              <p className="text-xs uppercase text-slate-500">{key.replaceAll("_", " ")}</p>
              <p className="mt-2 text-2xl font-semibold text-white">{value.score}/10</p>
              <p className="mt-2 text-sm text-slate-400">{value.reasoning}</p>
            </div>
          ))}
        </div>
      </div>
      <div className="panel rounded-lg p-5">
        <h2 className="text-lg font-semibold text-white">Prioritized transition roadmap</h2>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          {(pqc.recommendations || []).map((item) => <div key={item} className="rounded-md border border-line bg-ink/60 p-3 text-sm text-slate-300">{item}</div>)}
        </div>
      </div>
    </div>
  );
}

