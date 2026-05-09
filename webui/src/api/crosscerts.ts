import { apiJson, ApiError } from './client';
import { apiPath, apiListPath } from './paths';

export interface CrossCertRow {
  id: string;
  issuer_ca_id: string;
  subject_ca_id: string | null;
  subject_dn: string;
  serial_number: string;
  not_before: number;
  not_after: number;
  created: number;
  cross_cert_pem?: string;
  cert_text: string | null;
}

export interface CrossCertListParams {
  ca_id?: string;
  limit?: number;
  offset?: number;
}

export async function listCrossCerts(params: CrossCertListParams = {}): Promise<{ cross_certs: CrossCertRow[]; total: number; limit: number; offset: number }> {
  const qs = new URLSearchParams();
  if (params.ca_id) qs.set('ca_id', params.ca_id);
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return apiJson(`${apiListPath('cross-cert')}?${qs}`);
}

export async function getCrossCert(id: string): Promise<CrossCertRow> {
  return apiJson(apiPath('cross-cert', id));
}

export async function downloadCrossCert(id: string): Promise<string> {
  const row = await getCrossCert(id);
  if (!row.cross_cert_pem) throw new ApiError(404, 'PEM not available');
  return row.cross_cert_pem;
}
