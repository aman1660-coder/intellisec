import { useState } from "react";
import { Link } from "react-router-dom";
import EmptyState from "../components/EmptyState";
import SeverityBadge from "../components/SeverityBadge";
import { useScans } from "../hooks/useScans";
import { cx } from "../utils/format";

export default function FindingsExplorer() {
  const { scans, loading } = useScans();
  const [filter, setFilter] = useState("all");

  if (loading) return <p className="text-slate-400">Loading findings...</p>;
  if (!scans.length) return <EmptyState title="No findings yet" />;

  const allFindings = scans.flatMap(scan => {
    return (scan.findings || []).map(finding => ({
      ...finding,
      scanId: scan.id,
      scanType: scan.scan_type,
      target: scan.normalized_target
    }));
  });

  const filteredFindings = filter === "all" ? allFindings : allFindings.filter(f => f.severity === filter);

  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm uppercase tracking-wide text-slate-500">Global Findings Explorer</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">All Vulnerabilities</h1>
      </div>

      <div className="flex gap-2 pb-2 overflow-x-auto border-b border-line">
        {["all", "critical", "high", "medium", "low", "info"].map((sev) => (
          <button
            key={sev}
            onClick={() => setFilter(sev)}
            className={cx(
              "px-3 py-1.5 text-sm font-medium rounded-t-md transition-colors",
              filter === sev ? "bg-panel2 text-cyanx border-b-2 border-cyanx" : "text-slate-400 hover:text-slate-200"
            )}
          >
            {sev.charAt(0).toUpperCase() + sev.slice(1)}
          </button>
        ))}
      </div>

      <div className="grid gap-4">
        {filteredFindings.length === 0 ? (
          <div className="text-slate-400 p-4 border border-line rounded-lg text-center">No findings matching this severity filter.</div>
        ) : (
          filteredFindings.map((finding) => (
            <Link key={`${finding.scanId}-${finding.finding_id}`} to={`/app/scans/${finding.scanId}/findings/${finding.finding_id || finding.id}`} className="block">
              <div className="panel rounded-lg p-4 hover:border-cyanx/50 transition-colors">
                <div className="flex flex-col justify-between gap-3 md:flex-row md:items-start">
                  <div>
                    <div className="flex gap-2 items-center mb-1">
                      <p className="text-xs uppercase text-slate-500">{finding.finding_type || "Vulnerability"}</p>
                      {finding.scanType === "security" ? (
                        <span className="text-[10px] uppercase font-bold text-gold bg-gold/10 px-1.5 py-0.5 rounded">AI Scan</span>
                      ) : (
                        <span className="text-[10px] uppercase font-bold text-cyanx bg-cyanx/10 px-1.5 py-0.5 rounded">Deterministic</span>
                      )}
                    </div>
                    <h2 className="mt-1 text-lg font-semibold text-white">{finding.title}</h2>
                    <p className="text-xs text-slate-400 mt-1">Target: {finding.target}</p>
                    <p className="mt-2 text-sm text-slate-400 line-clamp-2">{finding.description}</p>
                  </div>
                  <SeverityBadge severity={finding.severity} />
                </div>
              </div>
            </Link>
          ))
        )}
      </div>
    </div>
  );
}

