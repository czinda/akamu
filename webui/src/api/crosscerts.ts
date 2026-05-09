import { apiJson, apiFetch, ApiError } from './client';

export interface CrossCertRow {
  id: string;
  ca_id: string;
  subject_cn: string;
  not_before: string;
  not_after: string;
  cert_pem: string;
}

export interface CrossCertListParams {
  ca_id?: string;
  limit?: number;
  offset?: number;
}

export async function listCrossCerts(params: CrossCertListParams = {}): Promise<{ cross_certs: CrossCertRow[] }> {
  const qs = new URLSearchParams();
  if (params.ca_id) qs.set('ca_id', params.ca_id);
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return apiJson(`/admin/cross-certs?${qs}`);
}

export async function getCrossCert(id: string): Promise<CrossCertRow> {
  return apiJson(`/admin/cross-certs/${id}`);
}

export async function downloadCrossCert(id: string): Promise<string> {
  const resp = await apiFetch(`/admin/cross-certs/${id}/cert`);
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
  return resp.text();
}
