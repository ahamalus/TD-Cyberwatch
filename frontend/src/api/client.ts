/**
 * Minimal API client. Uses the httpOnly session cookie and sends the CSRF
 * token (double-submit cookie) on state-changing requests. Errors are mapped
 * to ApiError with the backend's structured error code and message.
 */

export class ApiError extends Error {
  status: number;
  code: string;
  details: unknown;
  requestId?: string;

  constructor(status: number, code: string, message: string, details?: unknown, requestId?: string) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
    this.requestId = requestId;
  }
}

const BASE = "/api/v1";

function csrfToken(): string | undefined {
  const m = document.cookie.match(/(?:^|; )cw_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : undefined;
}

type Query = Record<string, string | number | boolean | undefined | null | string[]>;

function buildUrl(path: string, query?: Query): string {
  const url = new URL(BASE + path, window.location.origin);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === null || v === "") continue;
      if (Array.isArray(v)) v.forEach((x) => url.searchParams.append(k, x));
      else url.searchParams.set(k, String(v));
    }
  }
  return url.pathname + url.search;
}

export async function request<T>(method: string, path: string, body?: unknown, query?: Query): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    const t = csrfToken();
    if (t) headers["X-CSRF-Token"] = t;
  }
  let res: Response;
  try {
    res = await fetch(buildUrl(path, query), {
      method,
      headers,
      credentials: "same-origin",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, "network_error", "Cannot reach the CyberWatch service. Check your connection and try again.");
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: unknown = undefined;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = undefined;
  }
  if (!res.ok) {
    const err = (data as { error?: { code: string; message: string; details?: unknown; request_id?: string } })?.error;
    throw new ApiError(
      res.status,
      err?.code ?? "http_error",
      err?.message ?? `Request failed (HTTP ${res.status}).`,
      err?.details,
      err?.request_id,
    );
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, query?: Query) => request<T>("GET", path, undefined, query),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body ?? {}),
  del: <T>(path: string) => request<T>("DELETE", path),
};

/** URL for a file download handled by the browser (cookie-authenticated GET). */
export function downloadUrl(path: string, query?: Query): string {
  return buildUrl(path, query);
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    if (Array.isArray(e.details) && e.details.length && typeof e.details[0] === "object") {
      const first = e.details[0] as { field?: string; message?: string };
      if (first.message) return `${e.message} ${first.field ? `${first.field}: ` : ""}${first.message}`;
    }
    if (Array.isArray(e.details) && e.details.length && typeof e.details[0] === "string") {
      return `${e.message} ${(e.details as string[]).join(" ")}`;
    }
    return e.message;
  }
  return "Something went wrong. Please try again.";
}
