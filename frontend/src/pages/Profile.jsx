import { useAuth } from "../context/AuthContext";
import { API_BASE } from "../services/api";

export default function Profile() {
  const { user } = useAuth();
  return (
    <div className="space-y-5">
      <div><p className="text-sm uppercase tracking-wide text-slate-500">Profile & Settings</p><h1 className="mt-2 text-3xl font-semibold text-white">Workspace settings</h1></div>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="panel rounded-lg p-5"><h2 className="font-semibold text-white">User</h2><p className="mt-3 text-slate-300">{user?.name}</p><p className="text-sm text-slate-500">{user?.email}</p></div>
        <div className="panel rounded-lg p-5"><h2 className="font-semibold text-white">API</h2><p className="mt-3 break-all text-sm text-slate-300">{API_BASE}</p><p className="mt-2 text-xs text-slate-500">Set VITE_API_URL for deployed frontend environments.</p></div>
      </div>
    </div>
  );
}

