const BASE = '';

function getToken(): string | null {
  try {
    const raw = sessionStorage.getItem('akamu_auth');
    if (raw) return (JSON.parse(raw) as { token: string | null }).token;
  } catch {
    // ignore
  }
  return null;
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

export async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await apiFetch(path, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, text || resp.statusText);
  }
  return resp.json() as Promise<T>;
}

export async function apiDelete(path: string): Promise<void> {
  const resp = await apiFetch(path, { method: 'DELETE' });
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, text || resp.statusText);
  }
}
