import { CheckCircle2, Loader2, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { scansApi } from "../services/api";
import { cx } from "../utils/format";

const stages = ["Initializing", "Validating Target", "Analyzing TLS", "Inspecting Certificate", "Checking Security Headers", "Building Attack Graph", "Calculating Contextual Risk", "Mapping Compliance Controls", "Assessing PQC Readiness", "Generating Intelligence Report"];

export default function NewScan() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [form, setForm] = useState({
    target_url: params.get("target") || "",
    authorization_confirmed: false,
    context: { website_category: "business", data_sensitivity: "moderate", exposure_type: "public", authentication_status: "unknown", business_criticality: "moderate" }
  });
  const [stage, setStage] = useState(0);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const progress = useMemo(() => Math.round(((stage + 1) / stages.length) * 100), [stage]);

  useEffect(() => {
    if (!running) return undefined;
    const timer = setInterval(() => setStage((current) => Math.min(stages.length - 1, current + 1)), 900);
    return () => clearInterval(timer);
  }, [running]);

  const updateContext = (key, value) => setForm((current) => ({ ...current, context: { ...current.context, [key]: value } }));
  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setRunning(true);
    setStage(0);
    try {
      const scan = await scansApi.create(form);
      setStage(stages.length - 1);
      navigate(`/app/scans/${scan.id}`);
    } catch (err) {
      setError(err.response?.data?.detail || "Scan failed.");
      setRunning(false);
    }
  };

  return (
    <div className="grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
      <form onSubmit={submit} className="panel rounded-lg p-5">
        <p className="text-sm uppercase tracking-wide text-slate-500">Guided Scan Workflow</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">New authorized scan</h1>
        <div className="mt-6 space-y-5">
          <label className="block">
            <span className="text-sm font-medium text-slate-300">Website URL</span>
            <input className="input mt-2" placeholder="https://example.com" value={form.target_url} onChange={(event) => setForm({ ...form, target_url: event.target.value })} required />
          </label>
          <div className="rounded-lg border border-gold/30 bg-gold/10 p-4">
            <div className="flex gap-3">
              <ShieldAlert className="mt-0.5 text-gold" size={20} />
              <div>
                <p className="font-semibold text-amber-100">Ethical-use confirmation</p>
                <p className="mt-1 text-sm text-slate-300">Only scan systems you own or are explicitly authorized to assess. IntelliSec blocks local and restricted network targets.</p>
              </div>
            </div>
            <label className="mt-4 flex items-center gap-3 text-sm text-slate-200">
              <input type="checkbox" checked={form.authorization_confirmed} onChange={(event) => setForm({ ...form, authorization_confirmed: event.target.checked })} required />
              I confirm ownership or written authorization.
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <label><span className="text-sm text-slate-300">Website category</span><select className="select mt-2" value={form.context.website_category} onChange={(e) => updateContext("website_category", e.target.value)}><option>business</option><option>ecommerce</option><option>healthcare</option><option>education</option><option>public-sector</option></select></label>
            <label><span className="text-sm text-slate-300">Data sensitivity</span><select className="select mt-2" value={form.context.data_sensitivity} onChange={(e) => updateContext("data_sensitivity", e.target.value)}><option>low</option><option>moderate</option><option>high</option><option>critical</option></select></label>
            <label><span className="text-sm text-slate-300">Exposure type</span><select className="select mt-2" value={form.context.exposure_type} onChange={(e) => updateContext("exposure_type", e.target.value)}><option>public</option><option>partner</option><option>internal</option></select></label>
            <label><span className="text-sm text-slate-300">Authentication</span><select className="select mt-2" value={form.context.authentication_status} onChange={(e) => updateContext("authentication_status", e.target.value)}><option>unknown</option><option>none</option><option>required</option></select></label>
            <label className="md:col-span-2"><span className="text-sm text-slate-300">Business criticality</span><select className="select mt-2" value={form.context.business_criticality} onChange={(e) => updateContext("business_criticality", e.target.value)}><option>low</option><option>moderate</option><option>high</option><option>critical</option></select></label>
          </div>
          {error && <p className="rounded-md border border-danger/30 bg-danger/10 p-3 text-sm text-rose-100">{error}</p>}
          <button className="btn-primary w-full" disabled={running}>{running ? "Scanning..." : "Run deterministic analysis"}</button>
        </div>
      </form>

      <div className="panel rounded-lg p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Scan Progress</h2>
          <span className="text-sm font-semibold text-cyanx">{running ? `${progress}%` : "Ready"}</span>
        </div>
        <div className="mt-4 h-2 rounded-full bg-line">
          <div className="h-2 rounded-full bg-cyanx transition-all" style={{ width: running ? `${progress}%` : "0%" }} />
        </div>
        <div className="mt-6 space-y-3">
          {stages.map((item, index) => (
            <div key={item} className={cx("flex items-center gap-3 rounded-md border p-3", running && index <= stage ? "border-cyanx/40 bg-cyanx/10" : "border-line bg-ink/60")}>
              {running && index === stage ? <Loader2 className="animate-spin text-cyanx" size={18} /> : <CheckCircle2 className={index < stage ? "text-leaf" : "text-slate-600"} size={18} />}
              <span className={cx("text-sm", running && index <= stage ? "text-white" : "text-slate-500")}>{item}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

