export const base = import.meta.env.VITE_API_URL ?? "";
export const token = () => localStorage.getItem("as_token");
export function setToken(t: string | null) { t ? localStorage.setItem("as_token", t) : localStorage.removeItem("as_token"); }
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${base}${path}`, { ...init, headers: { "Content-Type": "application/json", ...(token() ? { Authorization: `Bearer ${token()}` } : {}), ...(init.headers ?? {}) } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
  return (body.data ?? body) as T;
}
export const post = <T,>(p: string, b: unknown) => api<T>(p, { method: "POST", body: JSON.stringify(b) });
