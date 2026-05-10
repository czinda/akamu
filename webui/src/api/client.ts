const BASE = '';

function getToken(): string | null {
  const raw = sessionStorage.getItem('akamu_auth');
  if (!raw) return null;
  try {
    return (JSON.parse(raw) as { token: string | null }).token;
  } catch {
    console.warn('akamu: corrupt akamu_auth entry in sessionStorage removed');
    sessionStorage.removeItem('akamu_auth');
    return null;
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string>),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (init?.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  const resp = await fetch(`${BASE}${path}`, { ...init, headers });
  if (resp.status === 401) {
    // Token expired — trigger re-login by clearing storage.
    sessionStorage.removeItem('akamu_auth');
    window.location.href = '/ui/login';
    throw new ApiError(401, 'session expired');
  }
  return resp;
}

export function extractErrorMessage(status: number, text: string, statusText: string): string {
  if (text) {
    try {
      const body = JSON.parse(text) as Record<string, unknown>;
      if (typeof body.detail === 'string' && body.detail) {
        const prefix =
          status === 403 ? 'Access denied' :
          status === 404 ? 'Not found' :
          status === 409 ? 'Conflict' :
          status === 400 ? 'Bad request' :
          status >= 500 ? 'Server error' : null;
        return prefix ? `${prefix}: ${body.detail}` : body.detail;
      }
    } catch {
      // not JSON — fall through to raw text
    }
    return text;
  }
  return statusText;
}

export async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await apiFetch(path, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, extractErrorMessage(resp.status, text, resp.statusText));
  }
  return resp.json() as Promise<T>;
}

export async function apiDelete(path: string): Promise<void> {
  const resp = await apiFetch(path, { method: 'DELETE' });
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, extractErrorMessage(resp.status, text, resp.statusText));
  }
}

export async function apiVoid(path: string, init?: RequestInit): Promise<void> {
  const resp = await apiFetch(path, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, extractErrorMessage(resp.status, text, resp.statusText));
  }
}
