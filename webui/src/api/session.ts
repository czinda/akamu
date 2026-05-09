import { apiFetch, ApiError } from './client';
import type { Role } from '../auth/AuthContext';

export interface SessionResponse {
  session_token: string;
  role: Role;
  operator: string;
  expires_at: string;
}

export async function loginGssapi(): Promise<SessionResponse> {
  // Step 1: send unauthenticated POST → server returns 401 + WWW-Authenticate: Negotiate
  // Step 2: browser retries automatically with Kerberos ticket (in supported browsers)
  // We just POST with no credentials and rely on the browser's SPNEGO support.
  const resp = await fetch('/admin/session', {
    method: 'POST',
    credentials: 'include',
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, text || resp.statusText);
  }
  return resp.json() as Promise<SessionResponse>;
}

export async function loginEab(kid: string, hmacKey: string): Promise<SessionResponse> {
  const timestamp = Math.floor(Date.now() / 1000);
  const message = `${kid}.${timestamp}`;

  // Compute HMAC-SHA256 using the Web Crypto API.
  const keyBytes = base64urlDecode(hmacKey) as Uint8Array<ArrayBuffer>;
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const msgBytes = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, msgBytes);
  const signature = base64urlEncode(new Uint8Array(sig as ArrayBuffer));

  const resp = await fetch('/admin/session/eab', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kid, timestamp, signature }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, text || resp.statusText);
  }
  return resp.json() as Promise<SessionResponse>;
}

export async function logout(): Promise<void> {
  try {
    await apiFetch('/admin/session', { method: 'DELETE' });
  } catch {
    // Best-effort — clear local state regardless.
  }
}

export async function whoami(): Promise<SessionResponse> {
  const resp = await apiFetch('/admin/session', { method: 'POST' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
  return resp.json() as Promise<SessionResponse>;
}

function base64urlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + ((4 - (s.length % 4)) % 4), '=');
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
