import { apiJson, apiDelete } from './client';
import { apiPath, apiListPath } from './paths';

export interface EabKeyRow {
  kid: string;
  alg: string;
  created: number;
  used_at: number | null;
  profile_grants: string[] | null;
  bound_principal: string | null;
  created_by_operator_id: string | null;
}

export interface EabListParams {
  used?: boolean;
  limit?: number;
  offset?: number;
}

export async function listEab(params: EabListParams = {}): Promise<{ eab_keys: EabKeyRow[]; total: number; limit: number; offset: number }> {
  const qs = new URLSearchParams();
  if (params.used !== undefined) qs.set('used', String(params.used));
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return apiJson(`${apiListPath('eab')}?${qs}`);
}

export async function getEab(kid: string): Promise<EabKeyRow> {
  return apiJson(apiPath('eab', kid));
}

export interface CreateEabOptions {
  kid: string;
  hmac_key_b64u: string;
  alg?: string;
  profile_grants?: string[];
  /** Operator ID this key logs in as (admins only; defaults to the caller). */
  for_operator_id?: number;
}

export async function createEab(opts: CreateEabOptions): Promise<{ kid: string; created: number }> {
  return apiJson(apiListPath('eab'), {
    method: 'POST',
    body: JSON.stringify(opts),
  });
}

export async function deleteEab(kid: string): Promise<void> {
  return apiDelete(apiPath('eab', kid));
}
