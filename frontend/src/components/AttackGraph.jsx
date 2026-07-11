import SeverityBadge from "./SeverityBadge";

export default function AttackGraph({ graph, paths = [] }) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  return (
    <div className="grid gap-5 lg:grid-cols-[1.2fr_0.8fr]">
      <div className="quiet-panel rounded-lg p-4">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-300">Directed Finding Graph</h3>
          <span className="text-xs text-slate-500">{edges.length} relationships</span>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          {nodes.map((node) => (
            <div key={node.id} className="rounded-md border border-line bg-ink/60 p-3">
              <div className="flex items-start justify-between gap-2">
                <p className="text-sm font-medium text-white">{node.label}</p>
                <SeverityBadge severity={node.severity} />
              </div>
              <p className="mt-2 text-xs text-slate-500">{node.type}</p>
            </div>
          ))}
        </div>
        {edges.length > 0 && (
          <div className="mt-5 space-y-2">
            {edges.map((edge, index) => {
              const source = nodes.find((node) => node.id === edge.source);
              const target = nodes.find((node) => node.id === edge.target);
              return (
                <div key={`${edge.source}-${edge.target}-${index}`} className="rounded-md border border-cyanx/20 bg-cyanx/5 p-3 text-sm text-slate-300">
                  <span className="font-semibold text-cyan-100">{source?.label}</span>
                  <span className="px-2 text-cyanx">-&gt;</span>
                  <span className="font-semibold text-cyan-100">{target?.label}</span>
                  <p className="mt-1 text-xs text-slate-500">{edge.relationship}</p>
                </div>
              );
            })}
          </div>
        )}
      </div>
      <div className="space-y-3">
        {paths.map((path) => (
          <div key={path.chain_id} className="panel rounded-lg p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">{path.chain_id}</p>
                <h3 className="mt-1 text-lg font-semibold text-white">{path.final_composite_score}/10</h3>
              </div>
              <SeverityBadge severity={path.severity} />
            </div>
            <p className="mt-3 text-sm text-slate-300">{path.technical_narrative}</p>
            <div className="mt-3 grid grid-cols-3 gap-2 text-center text-xs">
              <div className="rounded-md bg-white/5 p-2">
                <p className="text-slate-500">Length</p>
                <p className="font-semibold text-white">{path.chain_length}</p>
              </div>
              <div className="rounded-md bg-white/5 p-2">
                <p className="text-slate-500">Mean</p>
                <p className="font-semibold text-white">{path.mean_base_score}</p>
              </div>
              <div className="rounded-md bg-white/5 p-2">
                <p className="text-slate-500">Alpha</p>
                <p className="font-semibold text-white">{path.amplification_factor}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

