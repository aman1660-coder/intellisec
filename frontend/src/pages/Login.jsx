import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      await login(form);
      navigate("/app/dashboard");
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed.");
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
        <h1 className="mt-8 text-2xl font-semibold text-white">Welcome back</h1>
        <p className="mt-2 text-sm text-slate-400">Access your scan history and security posture dashboards.</p>
        {error && <p className="mt-4 rounded-md border border-danger/30 bg-danger/10 p-3 text-sm text-rose-100">{error}</p>}
        <div className="mt-5 space-y-4">
          <input className="input" type="email" placeholder="Email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} required />
          <input className="input" type="password" placeholder="Password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} required />
        </div>
        <button className="btn-primary mt-5 w-full" disabled={loading}>{loading ? "Signing in..." : "Login"}</button>
        <p className="mt-4 text-center text-sm text-slate-400">New to IntelliSec? <Link className="text-cyanx" to="/register">Create account</Link></p>
      </form>
    </div>
  );
}

