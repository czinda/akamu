import { apiJson, apiFetch, ApiError, extractErrorMessage } from './client';
import { apiPath, apiListPath } from './paths';

export interface CertRow {
  id: string;
  order_id: string | null;
  account_id: string;
  ca_id: string;
  serial_number: string;
  subject_dn: string;
  status: string;
  not_before: number | null;
  not_after: number | null;
  revoked_at: number | null;
  revocation_reason: string | null;
  mtc_log_index: number | null;
  created: number;
  suggested_window_start: number | null;
  suggested_window_end: number | null;
  replaced_by: string | null;
  cert_text: string | null;
}

export interface CertListParams {
  ca_id?: string;
  account_id?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

export async function listCerts(params: CertListParams = {}): Promise<{ certs: CertRow[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.ca_id) qs.set('ca_id', params.ca_id);
  if (params.account_id) qs.set('account_id', params.account_id);
  if (params.status) qs.set('status', params.status);
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return apiJson(`${apiListPath('cert')}?${qs}`);
}

export async function getCert(id: string): Promise<CertRow> {
  return apiJson(apiPath('cert', id));
}

export async function downloadCert(id: string): Promise<string> {
  const resp = await apiFetch(`${apiPath('cert', id)}/download`);
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
  return resp.text();
}

export async function revokeCert(id: string, reason: number = 0): Promise<void> {
  const resp = await apiFetch('/admin/revoke', {
    method: 'POST',
    body: JSON.stringify({ cert_id: id, reason }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, extractErrorMessage(resp.status, text, resp.statusText));
  }
}
