import { useMemo, useState } from "react";
import { Download, FileJson, ShieldCheck } from "lucide-react";
import MetricCard from "./MetricCard";
import SeverityBadge from "./SeverityBadge";
import AttackGraph from "./AttackGraph";
import { ComplianceBars, RiskRadar, SeverityPie } from "../charts/RiskCharts";
import { cx, dateShort, frameworkColor } from "../utils/format";

const tabs = ["Overview", "Findings", "Attack Paths", "Contextual Risk", "TLS & Cryptography", "Certificate", "HTTP Headers", "Compliance", "PQC Readiness", "AI Intelligence", "Reports"];

function exportJson(scan) {
  const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `intellisec-${scan.id || "scan"}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

export default function ScanReportView({ scan }) {
  const [active, setActive] = useState("Overview");
  const severityCounts = useMemo(() => {
    return (scan.findings || []).reduce((acc, item) => {
      acc[item.severity] = (acc[item.severity] || 0) + 1;
      return acc;
    }, {});
  }, [scan]);

  return (
    <div className="space-y-6">
      <div className="panel rounded-lg p-5">
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-cyanx/40 bg-cyanx/10 px-3 py-1 text-xs font-semibold text-cyan-100">{scan.scan_mode}</span>
              <span className="rounded-full border border-line px-3 py-1 text-xs text-slate-400">{dateShort(scan.timestamp)}</span>
            </div>
            <h1 className="mt-3 text-3xl font-semibold text-white">{scan.normalized_target || scan.target}</h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">{scan.data_mode_notice}</p>
          </div>
          <div className="flex gap-3">
            <button className="btn-secondary" onClick={() => window.print()}>
              <Download size={16} />
              Print
            </button>
            <button className="btn-primary" onClick={() => exportJson(scan)}>
              <FileJson size={16} />
              JSON
            </button>
          </div>
        </div>
      </div>

      <div className="scrollbar flex gap-2 overflow-x-auto rounded-lg border border-line bg-panel/60 p-2">
        {tabs.map((tab) => (
          <button key={tab} className={cx("tab whitespace-nowrap", active === tab && "tab-active")} onClick={() => setActive(tab)}>
            {tab}
          </button>
        ))}
      </div>

      {active === "Overview" && (
        <div className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
            <MetricCard icon={ShieldCheck} label="IntelliSec Score" value={scan.intellisec_score ?? 0} detail="0-100 posture score" />
            <MetricCard label="Findings" value={scan.findings?.length || 0} detail={`${severityCounts.critical || 0} critical, ${severityCounts.high || 0} high`} tone="amber" />
            <MetricCard label="Critical Paths" value={scan.attack_paths?.filter((p) => p.severity === "critical").length || 0} detail={`${scan.attack_paths?.length || 0} active chains`} tone="rose" />
            <MetricCard label="Compliance Mappings" value={scan.compliance_mappings?.length || 0} detail="technical indicators" tone="green" />
            <MetricCard label="PQC Score" value={`${scan.pqc_readiness?.score ?? "NA"}/10`} detail={scan.pqc_readiness?.classification} tone="blue" />
          </div>
          <div className="grid gap-5 lg:grid-cols-2">
            <div className="panel rounded-lg p-5">
              <h2 className="text-lg font-semibold text-white">Risk Distribution</h2>
              <SeverityPie findings={scan.findings || []} />
            </div>
            <div className="panel rounded-lg p-5">
              <h2 className="text-lg font-semibold text-white">Five-Factor Risk</h2>
              <RiskRadar risk={scan.risk_assessment} />
            </div>
          </div>
          <div className="panel rounded-lg p-5">
            <h2 className="text-lg font-semibold text-white">Top Remediation Actions</h2>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {(scan.findings || [])
                .slice()
                .sort((a, b) => b.base_score - a.base_score)
                .slice(0, 6)
                .map((finding) => (
                  <div key={finding.finding_id} className="rounded-md border border-line bg-ink/60 p-3">
                    <div className="flex items-start justify-between gap-3">
                      <p className="font-medium text-white">{finding.title}</p>
                      <SeverityBadge severity={finding.severity} />
                    </div>
                    <p className="mt-2 text-sm text-slate-400">{finding.remediation}</p>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {active === "Findings" && (
        <div className="grid gap-3">
          {(scan.findings || []).map((finding) => (
            <div key={finding.finding_id} className="panel rounded-lg p-4">
              <div className="flex flex-col justify-between gap-3 md:flex-row md:items-start">
                <div>
                  <p className="text-xs uppercase tracking-wide text-slate-500">{finding.category}</p>
                  <h2 className="mt-1 text-lg font-semibold text-white">{finding.title}</h2>
                  <p className="mt-2 text-sm text-slate-400">{finding.description}</p>
                </div>
                <SeverityBadge severity={finding.severity} />
              </div>
              <div className="mt-4 grid gap-3 lg:grid-cols-2">
                <pre className="overflow-auto rounded-md border border-line bg-ink/80 p-3 text-xs text-slate-300">{JSON.stringify(finding.evidence, null, 2)}</pre>
                <div className="rounded-md border border-line bg-panel2 p-3 text-sm text-slate-300">
                  <p className="font-semibold text-white">Remediation</p>
                  <p className="mt-2">{finding.remediation}</p>
                  <p className="mt-3 text-xs text-slate-500">{finding.deterministic_status} - {finding.affected_component}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {active === "Attack Paths" && <AttackGraph graph={scan.attack_graph} paths={scan.attack_paths || []} />}

      {active === "Contextual Risk" && (
        <div className="grid gap-5 lg:grid-cols-[0.9fr_1.1fr]">
          <div className="panel rounded-lg p-5">
            <h2 className="text-lg font-semibold text-white">Contextual Score</h2>
            <p className="mt-2 text-5xl font-semibold text-cyanx">{scan.risk_assessment?.final_score}/10</p>
            <p className="mt-2 text-sm text-slate-400">{scan.risk_assessment?.normalization}</p>
            <p className="mt-4 text-sm text-slate-300">Base mean: {scan.risk_assessment?.base_severity_mean} | Contextual delta: {scan.risk_assessment?.contextual_delta}</p>
          </div>
          <div className="panel rounded-lg p-5">
            <RiskRadar risk={scan.risk_assessment} />
          </div>
          <div className="lg:col-span-2 grid gap-3 md:grid-cols-5">
            {Object.entries(scan.risk_assessment?.dimensions || {}).map(([key, item]) => (
              <div key={key} className="quiet-panel rounded-lg p-4">
                <p className="text-xs uppercase text-slate-500">{key.replaceAll("_", " ")}</p>
                <p className="mt-2 text-2xl font-semibold text-white">{item.score}/2</p>
                <p className="mt-2 text-xs text-slate-400">{item.reasoning}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {active === "TLS & Cryptography" && (
        <div className="grid gap-4 md:grid-cols-2">
          {Object.entries(scan.tls?.protocols || {}).map(([name, item]) => (
            <div key={name} className="panel rounded-lg p-4">
              <p className="text-sm text-slate-500">{name}</p>
              <p className={cx("mt-2 text-2xl font-semibold", item.supported ? "text-leaf" : "text-slate-300")}>{item.supported ? "Supported" : "Not supported"}</p>
              <pre className="mt-3 overflow-auto rounded-md bg-ink/80 p-3 text-xs text-slate-400">{JSON.stringify(item, null, 2)}</pre>
            </div>
          ))}
          <div className="panel rounded-lg p-4 md:col-span-2">
            <h2 className="text-lg font-semibold text-white">Negotiated Session</h2>
            <pre className="mt-3 overflow-auto rounded-md bg-ink/80 p-3 text-xs text-slate-300">{JSON.stringify(scan.tls?.negotiated || {}, null, 2)}</pre>
          </div>
        </div>
      )}

      {active === "Certificate" && (
        <div className="panel rounded-lg p-5">
          <h2 className="text-lg font-semibold text-white">Certificate Intelligence</h2>
          <pre className="mt-4 overflow-auto rounded-md border border-line bg-ink/80 p-4 text-sm text-slate-300">{JSON.stringify(scan.tls?.certificate || "Not assessed", null, 2)}</pre>
        </div>
      )}

      {active === "HTTP Headers" && (
        <div className="grid gap-3 md:grid-cols-2">
          {(scan.http?.headers || []).map((header) => (
            <div key={header.header} className="quiet-panel rounded-lg p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="font-medium text-white">{header.header}</p>
                <span className={cx("rounded-full px-2 py-1 text-xs font-semibold", header.present ? "bg-leaf/10 text-leaf" : "bg-danger/10 text-rose-200")}>{header.present ? "present" : "absent"}</span>
              </div>
              <p className="mt-2 break-words text-sm text-slate-400">{header.observed_value || header.recommended_value}</p>
            </div>
          ))}
          <div className="panel rounded-lg p-4 md:col-span-2">
            <h2 className="text-lg font-semibold text-white">Cookie Observations</h2>
            <pre className="mt-3 overflow-auto rounded-md bg-ink/80 p-3 text-xs text-slate-300">{JSON.stringify(scan.http?.cookies || [], null, 2)}</pre>
          </div>
        </div>
      )}

      {active === "Compliance" && (
        <div className="grid gap-5 lg:grid-cols-[0.9fr_1.1fr]">
          <div className="panel rounded-lg p-5">
            <h2 className="text-lg font-semibold text-white">Framework Coverage</h2>
            <ComplianceBars mappings={scan.compliance_mappings || []} />
            <p className="mt-2 text-xs text-slate-500">{scan.compliance_summary?.disclaimer}</p>
          </div>
          <div className="space-y-3">
            {(scan.compliance_mappings || []).map((item) => (
              <div key={item.mapping_id} className="quiet-panel rounded-lg p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={cx("rounded-full border px-2.5 py-1 text-xs font-semibold", frameworkColor(item.framework))}>{item.framework}</span>
                  <span className="text-sm font-semibold text-white">{item.control}</span>
                </div>
                <p className="mt-2 text-sm text-slate-300">{item.finding_title}</p>
                <p className="mt-1 text-xs text-slate-500">{item.explanation}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {active === "PQC Readiness" && (
        <div className="grid gap-5 lg:grid-cols-[0.8fr_1.2fr]">
          <div className="panel rounded-lg p-5">
            <p className="text-sm uppercase tracking-wide text-slate-500">PQC readiness</p>
            <p className="mt-3 text-6xl font-semibold text-gold">{scan.pqc_readiness?.score}/10</p>
            <p className="mt-2 text-xl font-semibold text-white">{scan.pqc_readiness?.classification}</p>
            <p className="mt-3 text-sm text-slate-400">2035 migration window: {scan.pqc_readiness?.years_until_2035} years remaining.</p>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            {Object.entries(scan.pqc_readiness?.dimensions || {}).map(([key, item]) => (
              <div key={key} className="quiet-panel rounded-lg p-4">
                <p className="text-xs uppercase text-slate-500">{key.replaceAll("_", " ")}</p>
                <p className="mt-2 text-2xl font-semibold text-white">{item.score}/10</p>
                <p className="mt-2 text-sm text-slate-400">{item.reasoning}</p>
              </div>
            ))}
          </div>
          <div className="panel rounded-lg p-5 lg:col-span-2">
            <h2 className="text-lg font-semibold text-white">Transition Roadmap</h2>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {(scan.pqc_readiness?.recommendations || []).map((item) => (
                <div key={item} className="rounded-md border border-line bg-ink/60 p-3 text-sm text-slate-300">{item}</div>
              ))}
            </div>
          </div>
        </div>
      )}

      {active === "AI Intelligence" && (
        <div className="panel rounded-lg p-5">
          <h2 className="text-lg font-semibold text-white">Controlled AI Interpretation</h2>
          <p className="mt-2 text-sm text-slate-400">Provider: {scan.ai_interpretation?.provider}. AI receives structured findings only, never raw page content.</p>
          <pre className="mt-4 overflow-auto rounded-md border border-line bg-ink/80 p-4 text-sm text-slate-300">{JSON.stringify(scan.ai_interpretation, null, 2)}</pre>
        </div>
      )}

      {active === "Reports" && (
        <div className="grid gap-5 lg:grid-cols-3">
          {["developer", "compliance", "executive"].map((name) => (
            <div key={name} className="panel rounded-lg p-5">
              <p className="text-xs uppercase tracking-wide text-slate-500">{name}</p>
              <h2 className="mt-2 text-lg font-semibold text-white">{scan.reports?.[name]?.title}</h2>
              <pre className="mt-4 max-h-[520px] overflow-auto whitespace-pre-wrap rounded-md bg-ink/80 p-3 text-xs text-slate-300">{JSON.stringify(scan.reports?.[name], null, 2)}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

