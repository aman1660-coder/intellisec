import { BarChart3, Binary, ClipboardCheck, FileText, GitBranch, History, Home, LogOut, Radar, Search, Settings, Shield, ShieldCheck, Sparkles } from "lucide-react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { cx } from "../utils/format";

const links = [
  { to: "/app/dashboard", label: "Dashboard", icon: Home },
  { to: "/app/new-scan", label: "New Scan", icon: Search },
  { to: "/app/history", label: "History", icon: History },
  { to: "/app/findings", label: "Findings", icon: Shield },
  { to: "/app/attack-paths", label: "Attack Paths", icon: GitBranch },
  { to: "/app/compliance", label: "Compliance", icon: ClipboardCheck },
  { to: "/app/pqc", label: "PQC", icon: Binary },
  { to: "/app/compare", label: "Compare", icon: BarChart3 },
  { to: "/app/research", label: "Research", icon: Sparkles },
  { to: "/app/profile", label: "Settings", icon: Settings }
];

export default function AppLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  return (
    <div className="min-h-screen bg-ink text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-72 border-r border-line bg-ink/95 p-5 lg:block">
        <NavLink to="/" className="flex items-center gap-3">
          <div className="rounded-md bg-cyanx p-2 text-ink">
            <ShieldCheck size={22} />
          </div>
          <div>
            <p className="text-lg font-bold text-white">IntelliSec</p>
            <p className="text-xs text-slate-500">Posture Intelligence</p>
          </div>
        </NavLink>
        <nav className="mt-8 space-y-1">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} className={({ isActive }) => cx("flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition", isActive ? "bg-cyanx text-ink" : "text-slate-400 hover:bg-white/5 hover:text-white")}>
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="absolute bottom-5 left-5 right-5">
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <p className="text-sm font-semibold text-white">{user?.name}</p>
            <p className="truncate text-xs text-slate-500">{user?.email}</p>
          </div>
          <button
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-md border border-line px-3 py-2 text-sm text-slate-300 hover:bg-white/5"
            onClick={() => {
              logout();
              navigate("/");
            }}
          >
            <LogOut size={16} />
            Logout
          </button>
        </div>
      </aside>
      <main className="min-h-screen lg:pl-72">
        <header className="sticky top-0 z-10 border-b border-line bg-ink/85 px-4 py-3 backdrop-blur lg:hidden">
          <div className="flex items-center justify-between">
            <NavLink to="/app/dashboard" className="font-bold text-white">
              IntelliSec
            </NavLink>
            <NavLink to="/app/new-scan" className="btn-primary px-3 py-2">
              <Search size={16} />
            </NavLink>
          </div>
        </header>
        <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

