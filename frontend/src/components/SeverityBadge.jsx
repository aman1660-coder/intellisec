import { cx, severityColor } from "../utils/format";

export default function SeverityBadge({ severity }) {
  return (
    <span className={cx("inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold capitalize", severityColor(severity))}>
      {severity || "info"}
    </span>
  );
}

