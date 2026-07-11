export function cx(...parts) {
  return parts.filter(Boolean).join(" ");
}

export function severityColor(severity = "info") {
  return {
    critical: "border-rose-400/50 bg-rose-500/15 text-rose-200",
    high: "border-orange-400/50 bg-orange-500/15 text-orange-200",
    medium: "border-gold/50 bg-gold/15 text-amber-100",
    low: "border-cyanx/40 bg-cyanx/12 text-cyan-100",
    info: "border-slate-500/40 bg-slate-500/10 text-slate-200"
  }[severity] || "border-slate-500/40 bg-slate-500/10 text-slate-200";
}

export function frameworkColor(name = "") {
  if (name.includes("GDPR")) return "text-cyan-200 bg-cyan-500/10 border-cyan-500/30";
  if (name.includes("NIST")) return "text-emerald-200 bg-emerald-500/10 border-emerald-500/30";
  if (name.includes("PCI")) return "text-amber-100 bg-amber-500/10 border-amber-500/30";
  return "text-slate-200 bg-slate-500/10 border-slate-500/30";
}

export function dateShort(value) {
  if (!value) return "Not available";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

export function countsBy(items, key) {
  return items.reduce((acc, item) => {
    const value = item[key] || "unknown";
    acc[value] = (acc[value] || 0) + 1;
    return acc;
  }, {});
}

