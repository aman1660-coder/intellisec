export default function MetricCard({ icon: Icon, label, value, detail, tone = "cyan" }) {
  const toneClass = {
    cyan: "text-cyanx bg-cyanx/10",
    green: "text-leaf bg-leaf/10",
    amber: "text-gold bg-gold/10",
    rose: "text-danger bg-danger/10",
    blue: "text-sky-300 bg-sky-500/10"
  }[tone];
  return (
    <div className="quiet-panel rounded-lg p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
          <p className="mt-2 text-3xl font-semibold text-white">{value}</p>
          {detail && <p className="mt-1 text-sm text-slate-400">{detail}</p>}
        </div>
        {Icon && (
          <div className={`rounded-md p-2 ${toneClass}`}>
            <Icon size={19} />
          </div>
        )}
      </div>
    </div>
  );
}

