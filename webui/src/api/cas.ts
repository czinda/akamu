import { apiJson, apiFetch, ApiError } from './client';
import { apiPath, apiActionPath, apiListPath } from './paths';

export interface CaInfo {
  id: string;
  key_type: string;
  hash_alg: string;
  validity_days: number;
  is_default: boolean;
  cert_pem: string;
}

export async function listCas(): Promise<{ cas: CaInfo[] }> {
  return apiJson(apiListPath('ca'));
}

export async function getCa(id: string): Promise<CaInfo> {
  return apiJson(apiPath('ca', id));
}

export async function downloadCaCert(id: string): Promise<string> {
  const resp = await apiFetch(`${apiPath('ca', id)}/cert`);
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
  return resp.text();
}

export async function forceCrl(caId?: string): Promise<void> {
  const path = caId ? apiActionPath('ca', caId, 'crl/force') : '/admin/crl/force';
  const resp = await apiFetch(path, { method: 'POST' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export interface CrossSignResult {
  id: string;
  issuer_ca_id: string;
  subject_ca_id: string | null;
  subject_dn: string;
  serial_number: string;
  not_before: number;
  not_after: number;
  cross_cert_pem: string;
  created: number;
}

export type CrossSignOptions =
  | { subject_ca_id: string; validity_years?: number }
  | { subject_cert_pem: string; validity_years?: number };

export async function crossSign(caId: string, opts: CrossSignOptions): Promise<CrossSignResult> {
  return apiJson(apiActionPath('ca', caId, 'cross-sign'), {
    method: 'POST',
    body: JSON.stringify(opts),
  });
}
