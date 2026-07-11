import { useEffect, useState } from "react";
import { scansApi } from "../services/api";

export function useScans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    scansApi
      .list()
      .then((data) => active && setScans(data))
      .catch((err) => active && setError(err.response?.data?.detail || "Unable to load scans."))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, []);

  return { scans, loading, error, latest: scans[0] };
}

