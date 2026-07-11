import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import ScanReportView from "../components/ScanReportView";
import { scansApi } from "../services/api";

export default function ScanResults() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    scansApi
      .get(scanId)
      .then((data) => active && setScan(data))
      .catch((err) => active && setError(err.response?.data?.detail || "Unable to load scan."))
    return () => {
      active = false;
    };
  }, [scanId]);
  if (error) return <p className="rounded-md border border-danger/30 bg-danger/10 p-3 text-rose-100">{error}</p>;
  if (!scan) return <p className="text-slate-400">Loading scan results...</p>;
  return <ScanReportView scan={scan} />;
}

