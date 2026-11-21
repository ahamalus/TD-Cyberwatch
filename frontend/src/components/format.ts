import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import utc from "dayjs/plugin/utc";

dayjs.extend(relativeTime);
dayjs.extend(utc);

/** Consistent date-time format: 19 Oct 2026, 14:05 (local time). */
export function fmtDateTime(v?: string | null): string {
  return v ? dayjs(v).format("D MMM YYYY, HH:mm") : "—";
}

export function fmtDate(v?: string | null): string {
  return v ? dayjs(v).format("D MMM YYYY") : "—";
}

export function fmtRelative(v?: string | null): string {
  return v ? dayjs(v).fromNow() : "never";
}

export function fmtBytes(n?: number | null): string {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let x = n;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }
  return `${x.toFixed(x >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function fmtMoney(minor?: number | null, currency = "NGN"): string {
  if (minor === null || minor === undefined) return "—";
  return new Intl.NumberFormat("en-NG", { style: "currency", currency, maximumFractionDigits: 0 }).format(minor / 100);
}

const ACRONYMS = new Set(["tls", "sftp", "ssh", "api", "http", "https", "php", "dns", "uapi", "csv", "pdf", "mfa", "ip", "url", "soc", "whm", "tcp"]);

export function humanize(s?: string | null): string {
  if (!s) return "—";
  const words = s.replace(/[_:]/g, " ").split(" ").map((w) => (ACRONYMS.has(w.toLowerCase()) ? w.toUpperCase() : w));
  const t = words.join(" ");
  return t.charAt(0).toUpperCase() + t.slice(1);
}

export function fmtNumber(n?: number | null): string {
  return n === null || n === undefined ? "—" : new Intl.NumberFormat("en-NG").format(n);
}

export function shortHash(h?: string | null): string {
  return h ? `${h.slice(0, 12)}…` : "—";
}

/** Field description that shows a minimum-length rule, with live progress until it is met. */
export function minCharsHint(value: string, min: number, help?: string): string | undefined {
  const n = value.trim().length;
  const rule = n < min ? `At least ${min} characters (${n}/${min}).` : "";
  return [help, rule].filter(Boolean).join(" ") || undefined;
}

/** One-line description of a scan job: live progress while running, outcome when finished. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function scanJobDetail(j: { status: string; error_message?: string | null; result_summary?: any }): string {
  if (j.error_message) return j.error_message;
  const r = j.result_summary ?? {};
  if (j.status === "running" && r.progress) {
    const p = r.progress;
    return `${fmtNumber(p.files_seen)} files so far` + (p.files_reused ? ` · ${fmtNumber(p.files_reused)} unchanged (not re-downloaded)` : "");
  }
  if (r.files_seen === undefined) return "";
  let text = `${fmtNumber(r.files_seen)} files · ${fmtNumber(r.changes ?? 0)} changes`;
  if (r.files_reused) text += ` · ${fmtNumber(r.files_reused)} unchanged`;
  if ((r.limits_hit ?? []).includes("time")) text += " · time limit reached, the next scan continues";
  return text;
}

