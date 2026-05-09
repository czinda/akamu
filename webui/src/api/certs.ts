import { apiJson, apiFetch, ApiError } from './client';

export interface CertRow {
  id: string;
  serial: string;
  subject_dn: string;
  issuer_ca_id: string;
  account_id: string;
  not_before: string;
  not_after: string;
  revoked_at: string | null;
  revocation_reason: string | null;
}

export interface CertListParams {
  ca_id?: string;
  account_id?: string;
  revoked?: boolean;
  limit?: number;
  offset?: number;
}

export async function listCerts(params: CertListParams = {}): Promise<{ certs: CertRow[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.ca_id) qs.set('ca_id', params.ca_id);
  if (params.account_id) qs.set('account_id', params.account_id);
  if (params.revoked !== undefined) qs.set('revoked', String(params.revoked));
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return apiJson(`/admin/certs?${qs}`);
}

export async function getCert(id: string): Promise<CertRow> {
  return apiJson(`/admin/certs/${id}`);
}

export async function downloadCert(id: string): Promise<string> {
  const resp = await apiFetch(`/admin/certs/${id}/pem`);
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
  return resp.text();
}

export async function revokeCert(id: string, reason: string): Promise<void> {
  const resp = await apiFetch(`/admin/certs/${id}/revoke`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}
