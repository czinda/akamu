import { apiJson, apiFetch, ApiError } from './client';

export interface CaInfo {
  id: string;
  key_type: string;
  hash_alg: string;
  validity_days: number;
  is_default: boolean;
  cert_pem: string;
}

export async function listCas(): Promise<{ cas: CaInfo[] }> {
  return apiJson('/admin/cas');
}

export async function getCa(id: string): Promise<CaInfo> {
  return apiJson(`/admin/cas/${id}`);
}

export async function downloadCaCert(id: string): Promise<string> {
  const resp = await apiFetch(`/admin/cas/${id}/cert`);
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
  return resp.text();
}

export async function forceCrl(caId?: string): Promise<void> {
  const path = caId ? `/admin/cas/${caId}/crl` : '/admin/crl';
  const resp = await apiFetch(path, { method: 'POST' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export interface CrossSignOptions {
  cert_pem: string;
  ca_id?: string;
}

export async function crossSign(caId: string, opts: CrossSignOptions): Promise<{ id: string }> {
  return apiJson(`/admin/cas/${caId}/cross-sign`, {
    method: 'POST',
    body: JSON.stringify(opts),
  });
}
