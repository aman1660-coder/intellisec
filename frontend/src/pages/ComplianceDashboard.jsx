import EmptyState from "../components/EmptyState";
import { ComplianceBars } from "../charts/RiskCharts";
import { useScans } from "../hooks/useScans";
import { cx, frameworkColor } from "../utils/format";

export default function ComplianceDashboard() {
  const { latest, loading } = useScans();
  if (loading) return <p className="text-slate-400">Loading compliance mappings...</p>;
  if (!latest) return <EmptyState title="No compliance mappings yet" />;
  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm uppercase tracking-wide text-slate-500">Compliance Dashboard</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Technical-to-control mapping</h1>
        <p className="mt-2 text-sm text-slate-400">{latest.compliance_summary?.disclaimer}</p>
      </div>
      <div className="grid gap-5 lg:grid-cols-[0.8fr_1.2fr]">
        <div className="panel rounded-lg p-5"><ComplianceBars mappings={latest.compliance_mappings || []} /></div>
        <div className="space-y-3">
          {(latest.compliance_mappings || []).map((item) => (
            <div key={item.mapping_id} className="quiet-panel rounded-lg p-4">
              <span className={cx("rounded-full border px-2.5 py-1 text-xs font-semibold", frameworkColor(item.framework))}>{item.framework}</span>
              <p className="mt-2 font-semibold text-white">{item.control}</p>
              <p className="mt-1 text-sm text-slate-300">{item.finding_title}</p>
              <p className="mt-1 text-xs text-slate-500">{item.type} - {item.confidence} confidence</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

