import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import ScanReportView from "../components/ScanReportView";
import { scansApi } from "../services/api";

export default function CaseStudy() {
  const [scan, setScan] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    scansApi
      .caseStudy()
      .then((data) => active && setScan(data))
      .catch((err) => active && setError(err.response?.data?.detail || "Unable to load case study."))
    return () => {
      active = false;
    };
  }, []);
  if (error) return <div className="min-h-screen bg-ink p-8 text-rose-100">{error}</div>;
  if (!scan) return <div className="min-h-screen bg-ink p-8 text-slate-300">Loading research case study...</div>;
  return (
    <div className="min-h-screen bg-ink px-4 py-6 text-slate-100">
      <div className="mx-auto max-w-7xl">
        <div className="mb-4 flex items-center justify-between">
          <Link to="/" className="font-bold text-white">IntelliSec</Link>
          <Link to="/register" className="btn-primary">Create account</Link>
        </div>
        <ScanReportView scan={scan} />
      </div>
    </div>
  );
}

