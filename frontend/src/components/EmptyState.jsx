import { ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";

export default function EmptyState({ title = "No scans yet", message = "Run an authorized scan or open the research case study.", action = "/app/new-scan" }) {
  return (
    <div className="panel rounded-lg p-8 text-center">
      <ShieldAlert className="mx-auto text-cyanx" size={36} />
      <h2 className="mt-4 text-xl font-semibold text-white">{title}</h2>
      <p className="mx-auto mt-2 max-w-xl text-sm text-slate-400">{message}</p>
      <div className="mt-5 flex justify-center gap-3">
        <Link className="btn-primary" to={action}>
          New scan
        </Link>
        <Link className="btn-secondary" to="/case-study">
          Case study
        </Link>
      </div>
    </div>
  );
}

