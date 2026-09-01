import { CheckCircle2, Circle, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { securityApi } from "../services/api";
import { cx, formatError } from "../utils/format";

const ALL_PHASES = [
  { key: "target_validated", label: "Target validated" },
  { key: "environment_setup", label: "Environment setup" },
  { key: "reconnaissance", label: "Reconnaissance" },
  { key: "security_testing", label: "Security testing" },
  { key: "vulnerability_validation", label: "Vulnerability validation" },
  { key: "report_generation", label: "Report generation" },
];

export default function SecurityScanProgress() {
  const { scanId } = useParams();
  const [statusData, setStatusData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const fetchStatus = async () => {
      try {
        const data = await securityApi.status(scanId);
        if (active) setStatusData(data);
      } catch (err) {
        if (active) setError(formatError(err, "Failed to fetch status"));
      }
    };

    fetchStatus();
    const interval = setInterval(() => {
      if (statusData?.status === "completed" || statusData?.status === "failed") {
        clearInterval(interval);
      } else {
        fetchStatus();
      }
    }, 3000);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [scanId, statusData?.status]);

  if (error) {
    return <div className="rounded-md border border-danger/30 bg-danger/10 p-5 text-rose-100">{error}</div>;
  }

  if (!statusData) {
    return <div className="text-slate-400">Loading scan status...</div>;
  }

  const { status, scan_phases = {}, total_findings = 0 } = statusData;

  const completedCount = ALL_PHASES.filter((p) => scan_phases[p.key]).length;
  const progress = status === "completed" ? 100 : Math.round((completedCount / ALL_PHASES.length) * 100);
  const isRunning = status === "queued" || status === "running";

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <p className="text-sm uppercase tracking-wide text-slate-500">Scan Execution</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">AI Security Scan Progress</h1>
      </div>

      <div className="panel rounded-lg p-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Current Phase</h2>
          <span className="text-sm font-semibold text-cyanx">{progress}%</span>
        </div>
        <div className="mt-4 h-2 rounded-full bg-line">
          <div className="h-2 rounded-full bg-cyanx transition-all duration-500" style={{ width: `${progress}%` }} />
        </div>

        <div className="mt-6 flex items-center justify-between rounded-lg bg-ink/50 p-4 border border-line">
          <span className="text-slate-300">Live Vulnerabilities Discovered:</span>
          <span className="text-xl font-bold text-danger">{total_findings}</span>
        </div>

        <div className="mt-6 space-y-3">
          {ALL_PHASES.map((phase, index) => {
            const isCompleted = scan_phases[phase.key] === true;
            // Next phase after completed ones is active if running
            const isActive = isRunning && !isCompleted && (index === 0 || scan_phases[ALL_PHASES[index - 1].key] === true);
            const isPending = !isCompleted && !isActive;

            return (
              <div key={phase.key} className={cx("flex items-center gap-3 rounded-md border p-3", isActive ? "border-cyanx/40 bg-cyanx/10" : "border-line bg-ink/60")}>
                {isCompleted ? (
                  <CheckCircle2 className="text-leaf" size={18} />
                ) : isActive ? (
                  <Loader2 className="animate-spin text-cyanx" size={18} />
                ) : (
                  <Circle className="text-slate-600" size={18} />
                )}
                <span className={cx("text-sm", isActive || isCompleted ? "text-white" : "text-slate-500")}>
                  {phase.label}
                </span>
              </div>
            );
          })}
        </div>

        {status === "completed" && (
          <div className="mt-8 text-center space-y-4">
            <p className="text-leaf font-medium text-lg">✓ Scan completed successfully!</p>
            {statusData.security_score != null && (
              <div className="flex justify-center gap-6">
                <div className="quiet-panel rounded-lg px-6 py-3">
                  <p className="text-xs text-slate-500">Security Score</p>
                  <p className="text-2xl font-bold text-cyanx">{statusData.security_score}/100</p>
                </div>
                <div className="quiet-panel rounded-lg px-6 py-3">
                  <p className="text-xs text-slate-500">Findings</p>
                  <p className="text-2xl font-bold text-amber-200">{total_findings}</p>
                </div>
              </div>
            )}
            <Link to={`/app/scans/${scanId}`} className="btn-primary inline-flex w-full justify-center md:w-auto">
              View Final Report
            </Link>
          </div>
        )}

        {status === "failed" && (
          <div className="mt-8 rounded-md border border-danger/30 bg-danger/10 p-4 text-center">
            <p className="text-rose-100 font-medium">Scan failed to complete.</p>
            {statusData.error && <p className="mt-2 text-sm text-rose-200">{statusData.error}</p>}
            <p className="mt-2 text-sm text-slate-400">Please try again or check system logs.</p>
          </div>
        )}
      </div>
    </div>
  );
}
