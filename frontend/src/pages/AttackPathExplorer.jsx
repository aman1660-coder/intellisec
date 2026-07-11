import AttackGraph from "../components/AttackGraph";
import EmptyState from "../components/EmptyState";
import { useScans } from "../hooks/useScans";

export default function AttackPathExplorer() {
  const { latest, loading } = useScans();
  if (loading) return <p className="text-slate-400">Loading attack paths...</p>;
  if (!latest) return <EmptyState title="No attack paths yet" />;
  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm uppercase tracking-wide text-slate-500">Attack Path Explorer</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Correlated chains</h1>
      </div>
      <AttackGraph graph={latest.attack_graph} paths={latest.attack_paths || []} />
    </div>
  );
}

