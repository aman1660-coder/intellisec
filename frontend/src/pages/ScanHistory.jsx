import { Link } from "react-router-dom";
import EmptyState from "../components/EmptyState";
import SeverityBadge from "../components/SeverityBadge";
import { useScans } from "../hooks/useScans";
import { dateShort } from "../utils/format";

export default function ScanHistory() {
  const { scans, loading } = useScans();
  if (loading) return <p className="text-slate-400">Loading history...</p>;
  if (!scans.length) return <EmptyState title="No scan history yet" />;
  return (
    <div className="space-y-5">
      <div><p className="text-sm uppercase tracking-wide text-slate-500">Scan History</p><h1 className="mt-2 text-3xl font-semibold text-white">Historical posture tracking</h1></div>
      <div className="panel overflow-hidden rounded-lg">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="bg-panel2 text-slate-400"><tr><th className="p-4">Target</th><th className="p-4">Date</th><th className="p-4">Score</th><th className="p-4">Risk</th><th className="p-4">PQC</th></tr></thead>
          <tbody className="divide-y divide-line">
            {scans.map((scan) => (
              <tr key={scan.id} className="hover:bg-white/[0.02]">
                <td className="p-4"><Link className="font-medium text-white hover:text-cyanx" to={`/app/scans/${scan.id}`}>{scan.normalized_target}</Link></td>
                <td className="p-4 text-slate-400">{dateShort(scan.timestamp)}</td>
                <td className="p-4 font-semibold text-cyanx">{scan.intellisec_score}/100</td>
                <td className="p-4"><SeverityBadge severity={scan.risk_assessment?.severity} /></td>
                <td className="p-4 text-slate-300">{scan.pqc_readiness?.score}/10</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

