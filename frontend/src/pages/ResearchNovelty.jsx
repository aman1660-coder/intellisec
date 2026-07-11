import { Binary, Bot, ClipboardCheck, GitBranch, Radar, ShieldCheck } from "lucide-react";

const rows = [
  ["TLS & Crypto", "Cipher, forward secrecy, certificate, PQC, and compliance output", "7/10"],
  ["Scanner FP", "Deterministic binary checks before interpretation", "8/10"],
  ["Attack Chains", "Web exploit-chain engine with directed graph traversal", "9/10"],
  ["Compliance", "Finding-to-GDPR/NIST/PCI technical mapping", "8/10"],
  ["Risk Scoring", "Five-factor scoring with chain amplification", "8/10"],
  ["PQC Ready", "Automated web PQC readiness score", "9.5/10"]
];

export default function ResearchNovelty() {
  return (
    <div className="space-y-6">
      <div>
        <p className="text-sm uppercase tracking-wide text-slate-500">Research & Novelty</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Beyond a vulnerability scanner</h1>
        <p className="mt-3 max-w-4xl text-slate-400">The platform implements the paper's Generation-3 intelligence layer: deterministic findings are transformed into attacker-contextualized, governance-mapped, risk-prioritized, and quantum-aware guidance.</p>
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        {[
          [ShieldCheck, "Deterministic Detection", "LLMs never decide whether vulnerabilities exist."],
          [GitBranch, "Attack-Path Correlation", "Directed graph rules make chained risk visible."],
          [Radar, "Five-Factor Scoring", "Context alters priority beyond isolated severity."],
          [ClipboardCheck, "Compliance Mapping", "Technical findings map to named controls with disclaimers."],
          [Binary, "PQC Readiness", "TLS 1.3 is treated as a prerequisite, not PQC proof."],
          [Bot, "Controlled AI", "Narration and summaries operate only on structured JSON."]
        ].map(([Icon, title, copy]) => (
          <div key={title} className="panel rounded-lg p-5"><Icon className="text-cyanx" /><h2 className="mt-4 font-semibold text-white">{title}</h2><p className="mt-2 text-sm text-slate-400">{copy}</p></div>
        ))}
      </div>
      <div className="panel overflow-hidden rounded-lg">
        <table className="w-full min-w-[720px] text-left text-sm">
          <thead className="bg-panel2 text-slate-400"><tr><th className="p-4">Domain</th><th className="p-4">Contribution</th><th className="p-4">Paper novelty</th></tr></thead>
          <tbody className="divide-y divide-line">
            {rows.map((row) => <tr key={row[0]}>{row.map((cell) => <td key={cell} className="p-4 text-slate-300">{cell}</td>)}</tr>)}
          </tbody>
        </table>
      </div>
      <div className="panel rounded-lg p-5">
        <h2 className="text-lg font-semibold text-white">Research limitations preserved</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <p className="rounded-md bg-ink/70 p-3 text-sm text-slate-300">Correlation rules are hand-crafted and stored in a registry for future learned rules.</p>
          <p className="rounded-md bg-ink/70 p-3 text-sm text-slate-300">PQC thresholds and the 2035 timeline live in configuration and can be updated.</p>
          <p className="rounded-md bg-ink/70 p-3 text-sm text-slate-300">Role-specific LLM evaluation remains future work; fallback templates keep the platform functional.</p>
        </div>
      </div>
    </div>
  );
}

