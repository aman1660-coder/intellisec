import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      await register(form);
      const target = params.get("target");
      navigate(target ? `/app/new-scan?target=${encodeURIComponent(target)}` : "/app/dashboard");
    } catch (err) {
      setError(err.response?.data?.detail || "Registration failed.");
    } finally {
      setLoading(false);
    }
  };
  return (
    <div className="mesh flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit} className="panel w-full max-w-md rounded-lg p-6">
        <Link to="/" className="flex items-center gap-3">
          <span className="rounded-md bg-cyanx p-2 text-ink"><ShieldCheck size={21} /></span>
          <span className="text-lg font-bold text-white">IntelliSec</span>
        </Link>
        <h1 className="mt-8 text-2xl font-semibold text-white">Create your workspace</h1>
        <p className="mt-2 text-sm text-slate-400">Run authorized scans and track posture changes over time.</p>
        {error && <p className="mt-4 rounded-md border border-danger/30 bg-danger/10 p-3 text-sm text-rose-100">{error}</p>}
        <div className="mt-5 space-y-4">
          <input className="input" placeholder="Name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} required />
          <input className="input" type="email" placeholder="Email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} required />
          <input className="input" type="password" placeholder="Password, minimum 8 characters" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} required />
        </div>
        <button className="btn-primary mt-5 w-full" disabled={loading}>{loading ? "Creating..." : "Register"}</button>
        <p className="mt-4 text-center text-sm text-slate-400">Already registered? <Link className="text-cyanx" to="/login">Login</Link></p>
      </form>
    </div>
  );
}

