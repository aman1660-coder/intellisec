import { ArrowRight, Binary, Bot, ClipboardCheck, GitBranch, Radar, Search, ShieldCheck, Sparkles } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const pillars = [
  ["TLS & Crypto", "Cipher, certificate, protocol, and forward-secrecy intelligence."],
  ["Deterministic Detection", "Binary checks produce structured evidence before any AI narration."],
  ["Attack Paths", "NetworkX graph correlation turns isolated issues into chain-aware risk."],
  ["Compliance Mapping", "Finding-level GDPR, NIST, and PCI-DSS technical mappings."],
  ["Contextual Risk", "Five-factor model with chain amplification and business context."],
  ["PQC Readiness", "Quantum migration score aligned to the NIST 2035 transition window."]
];

export default function Landing() {
  const [target, setTarget] = useState("");
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();
  const begin = () => navigate(isAuthenticated ? `/app/new-scan?target=${encodeURIComponent(target)}` : `/register?target=${encodeURIComponent(target)}`);
  return (
    <div className="min-h-screen bg-ink text-slate-100">
      <nav className="fixed inset-x-0 top-0 z-30 border-b border-line bg-ink/78 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4">
          <Link to="/" className="flex items-center gap-3">
            <span className="rounded-md bg-cyanx p-2 text-ink"><ShieldCheck size={21} /></span>
            <span className="text-lg font-bold text-white">IntelliSec</span>
          </Link>
          <div className="hidden items-center gap-6 text-sm text-slate-400 md:flex">
            <a href="#workflow" className="hover:text-white">Workflow</a>
            <a href="#pillars" className="hover:text-white">Research Pillars</a>
            <a href="#pqc" className="hover:text-white">PQC</a>
            <Link to="/case-study" className="hover:text-white">Case Study</Link>
          </div>
          <div className="flex items-center gap-2">
            <Link to="/login" className="btn-secondary hidden sm:inline-flex">Login</Link>
            <Link to={isAuthenticated ? "/app/dashboard" : "/register"} className="btn-primary">Open app</Link>
          </div>
        </div>
      </nav>

      <section className="mesh relative overflow-hidden pt-28">
        <div className="mx-auto grid min-h-[86vh] max-w-7xl items-center gap-10 px-4 pb-16 lg:grid-cols-[1.05fr_0.95fr]">
          <div>
            <span className="inline-flex rounded-full border border-cyanx/40 bg-cyanx/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-cyan-100">Research implementation platform</span>
            <h1 className="mt-6 max-w-5xl text-5xl font-semibold leading-tight text-white md:text-7xl">IntelliSec</h1>
            <p className="mt-5 max-w-2xl text-lg text-slate-300">
              Intelligent web security posture management through deterministic analysis, attack-path correlation, compliance mapping, and post-quantum readiness assessment.
            </p>
            <div className="mt-8 rounded-lg border border-line bg-panel/80 p-3 shadow-glow">
              <div className="flex flex-col gap-3 sm:flex-row">
                <input className="input" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://authorized-site.example" />
                <button className="btn-primary sm:w-44" onClick={begin}>
                  <Search size={17} />
                  Start scan
                </button>
              </div>
              <p className="mt-2 text-xs text-slate-500">Authorized defensive assessment only. Local, private, metadata, and restricted network targets are blocked.</p>
            </div>
          </div>
          <div className="relative">
            <div className="panel rounded-lg p-5">
              <div className="grid gap-3">
                {["Deterministic Detection", "Attack Graph", "Contextual Risk", "Compliance + PQC", "AI Interpretation"].map((label, index) => (
                  <div key={label} className="flex items-center gap-3 rounded-md border border-line bg-ink/60 p-3">
                    <span className="flex h-8 w-8 items-center justify-center rounded-md bg-cyanx/10 text-sm font-bold text-cyanx">{index + 1}</span>
                    <div className="h-2 flex-1 rounded-full bg-line">
                      <div className="h-2 rounded-full bg-cyanx" style={{ width: `${96 - index * 12}%` }} />
                    </div>
                    <span className="w-40 text-sm font-medium text-slate-200">{label}</span>
                  </div>
                ))}
              </div>
              <div className="mt-5 grid grid-cols-3 gap-3">
                {["GDPR", "NIST", "PCI-DSS"].map((item) => (
                  <div key={item} className="rounded-md border border-leaf/20 bg-leaf/10 p-3 text-center text-sm font-semibold text-leaf">{item}</div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="workflow" className="border-y border-line bg-panel/40 py-16">
        <div className="mx-auto max-w-7xl px-4">
          <h2 className="text-3xl font-semibold text-white">How IntelliSec Works</h2>
          <div className="mt-8 grid gap-4 md:grid-cols-4">
            {[
              [ShieldCheck, "Detect", "TLS, certificates, headers, and cookies are assessed with deterministic checks."],
              [GitBranch, "Correlate", "Findings become nodes in a directed graph with documented amplification edges."],
              [Radar, "Score", "Risk is normalized across exploitability, sensitivity, crypto depth, exposure, and chains."],
              [Bot, "Interpret", "AI receives structured JSON after detection and has a deterministic fallback."]
            ].map(([Icon, title, copy]) => (
              <div key={title} className="quiet-panel rounded-lg p-5">
                <Icon className="text-cyanx" />
                <h3 className="mt-4 text-lg font-semibold text-white">{title}</h3>
                <p className="mt-2 text-sm text-slate-400">{copy}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="pillars" className="py-16">
        <div className="mx-auto max-w-7xl px-4">
          <div className="grid gap-8 lg:grid-cols-[0.75fr_1.25fr]">
            <div>
              <h2 className="text-3xl font-semibold text-white">Six Research Pillars</h2>
              <p className="mt-3 text-slate-400">A web security intelligence layer built around the paper's gap analysis, not a generic scanner wrapper.</p>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              {pillars.map(([title, copy]) => (
                <div key={title} className="panel rounded-lg p-5">
                  <h3 className="font-semibold text-white">{title}</h3>
                  <p className="mt-2 text-sm text-slate-400">{copy}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="border-y border-line bg-panel/40 py-16">
        <div className="mx-auto grid max-w-7xl gap-5 px-4 lg:grid-cols-3">
          <div className="panel rounded-lg p-6 lg:col-span-2">
            <h2 className="text-2xl font-semibold text-white">Attack-Path Correlation Demonstration</h2>
            <div className="mt-6 grid gap-3 md:grid-cols-3">
              {["Deprecated TLS", "Missing HSTS", "Insecure Cookie"].map((item, index) => (
                <div key={item} className="rounded-md border border-line bg-ink/70 p-4">
                  <p className="text-xs text-slate-500">Node {index + 1}</p>
                  <p className="mt-2 font-semibold text-white">{item}</p>
                </div>
              ))}
            </div>
            <p className="mt-5 text-sm text-slate-400">The backend computes alpha(k) = 1 + 0.35 ln(k), stores the graph edges, and exposes every chain as inspectable JSON.</p>
          </div>
          <div className="panel rounded-lg p-6">
            <h2 className="text-2xl font-semibold text-white">Contextual Risk</h2>
            <p className="mt-3 text-sm text-slate-400">Five dimensions explain why correlated medium findings can outrank isolated high findings for remediation.</p>
          </div>
        </div>
      </section>

      <section id="pqc" className="py-16">
        <div className="mx-auto grid max-w-7xl gap-5 px-4 lg:grid-cols-2">
          <div className="panel rounded-lg p-6">
            <Binary className="text-gold" />
            <h2 className="mt-4 text-3xl font-semibold text-white">Post-Quantum Readiness</h2>
            <p className="mt-3 text-slate-400">IntelliSec distinguishes classical crypto, TLS 1.3 migration prerequisites, hybrid readiness, and directly observed PQC indicators where detectable.</p>
          </div>
          <div className="panel rounded-lg p-6">
            <ClipboardCheck className="text-leaf" />
            <h2 className="mt-4 text-3xl font-semibold text-white">Compliance Mapping</h2>
            <p className="mt-3 text-slate-400">Findings map to GDPR Article 32, NIST SP 800-52/53/57/131A, and PCI-DSS references as technical alignment indicators with clear disclaimers.</p>
          </div>
        </div>
      </section>

      <section className="border-y border-line bg-panel/40 py-16">
        <div className="mx-auto max-w-7xl px-4">
          <h2 className="text-3xl font-semibold text-white">Research Novelty</h2>
          <div className="mt-6 overflow-hidden rounded-lg border border-line">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="bg-ink text-slate-300">
                <tr><th className="p-4">Capability</th><th className="p-4">Traditional Free Tools</th><th className="p-4">IntelliSec</th></tr>
              </thead>
              <tbody className="divide-y divide-line bg-panel/70 text-slate-300">
                {[
                  ["TLS analysis", "Supported by narrow tools", "Integrated with risk and compliance"],
                  ["Attack chains", "Not supported", "Directed graph correlation"],
                  ["Compliance mapping", "Manual or policy-level", "Finding-level GDPR/NIST/PCI mapping"],
                  ["PQC readiness", "No automated web score", "Four-dimension score"],
                  ["AI", "Often detector or report add-on", "Post-detection narration only"]
                ].map((row) => (
                  <tr key={row[0]}>{row.map((cell) => <td key={cell} className="p-4">{cell}</td>)}</tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link className="btn-primary" to="/case-study">
              Open case study
              <ArrowRight size={16} />
            </Link>
            <Link className="btn-secondary" to="/register">
              Create account
            </Link>
          </div>
        </div>
      </section>

      <section className="py-16">
        <div className="mx-auto max-w-7xl px-4">
          <div className="panel rounded-lg p-6">
            <Sparkles className="text-cyanx" />
            <h2 className="mt-4 text-2xl font-semibold text-white">Responsible Use</h2>
            <p className="mt-3 max-w-4xl text-slate-400">IntelliSec is restricted to owned or explicitly authorized targets. It does not brute force, exploit, exfiltrate, evade, persist, or perform destructive testing.</p>
          </div>
        </div>
      </section>

      <footer className="border-t border-line py-8">
        <div className="mx-auto flex max-w-7xl flex-col justify-between gap-3 px-4 text-sm text-slate-500 md:flex-row">
          <p>IntelliSec - Web Security Posture Intelligence Platform</p>
          <p>Deterministic detection first. AI interpretation second.</p>
        </div>
      </footer>
    </div>
  );
}

