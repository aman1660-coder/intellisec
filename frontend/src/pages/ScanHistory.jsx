import { Link } from "react-router-dom";
import EmptyState from "../components/EmptyState";
import SeverityBadge from "../components/SeverityBadge";
import { useScans } from "../hooks/useScans";
import { cx, dateShort } from "../utils/format";

export default function ScanHistory() {
  const { scans, loading } = useScans();
  if (loading) return <p className="text-slate-400">Loading history...</p>;
  if (!scans.length) return <EmptyState title="No scan history yet" />;

  const getStatusClass = (status) => {
    switch (status) {
      case "completed": return "text-leaf border-leaf bg-leaf/10";
      case "running": return "text-gold border-gold bg-gold/10";
      case "queued": return "text-cyanx border-cyanx bg-cyanx/10";
      case "failed": return "text-danger border-danger bg-danger/10";
      default: return "text-slate-400 border-slate-600 bg-slate-800/50";
    }
  };

  return (
    <div className="space-y-5">
      <div><p className="text-sm uppercase tracking-wide text-slate-500">Scan History</p><h1 className="mt-2 text-3xl font-semibold text-white">Historical posture tracking</h1></div>
      <div className="panel overflow-hidden rounded-lg">
        <table className="w-full min-w-[800px] text-left text-sm">
          <thead className="bg-panel2 text-slate-400">
            <tr>
              <th className="p-4">Target</th>
              <th className="p-4">Type</th>
              <th className="p-4">Date</th>
              <th className="p-4">Status</th>
              <th className="p-4">Risk</th>
              <th className="p-4">Vulns</th>
              <th className="p-4">Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {scans.map((scan) => (
              <tr key={scan.id} className="hover:bg-white/[0.02]">
                <td className="p-4">
                  <Link className="font-medium text-white hover:text-cyanx" to={`/app/scans/${scan.id}${scan.status !== "completed" && scan.status !== "failed" && scan.scan_type === "security" ? "/progress" : ""}`}>
                    {scan.normalized_target || scan.target_url}
                  </Link>
                </td>
                <td className="p-4 text-xs font-semibold uppercase text-slate-400">{scan.scan_type === "security" ? "AI Security" : scan.scan_mode || "Deterministic"}</td>
                <td className="p-4 text-slate-400">{dateShort(scan.timestamp)}</td>
                <td className="p-4">
                  <span className={cx("inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold capitalize", getStatusClass(scan.status))}>
                    {scan.status || "completed"}
                  </span>
                </td>
                <td className="p-4"><SeverityBadge severity={scan.risk_assessment?.severity || (scan.critical_count > 0 ? "critical" : scan.high_count > 0 ? "high" : "low")} /></td>
                <td className="p-4 text-slate-300">{scan.scan_type === "security" ? scan.total_findings || 0 : scan.findings?.length || 0}</td>
                <td className="p-4 font-semibold text-cyanx">{scan.scan_type === "security" ? scan.security_score : scan.intellisec_score}/100</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

