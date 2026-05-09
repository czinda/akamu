import { apiJson, apiFetch, ApiError } from './client';
import { apiPath, apiListPath } from './paths';

export interface DelegationRow {
  id: string;
  account_id: string;
  csr_template: unknown;   // JSON object from server
  cname_map: unknown | null;
  created: number;
  updated: number;
}

export interface DelegationListParams {
  account_id?: string;
  limit?: number;
  offset?: number;
}

export async function listDelegations(params: DelegationListParams = {}): Promise<{ delegations: DelegationRow[]; total: number; limit: number; offset: number }> {
  const qs = new URLSearchParams();
  if (params.account_id) qs.set('account_id', params.account_id);
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return apiJson(`${apiListPath('delegation')}?${qs}`);
}

export async function getDelegation(id: string): Promise<DelegationRow> {
  return apiJson(apiPath('delegation', id));
}

export interface DelegationCreatePayload {
  account_id: string;
  csr_template: unknown;
  cname_map?: unknown;
}

export interface DelegationUpdatePayload {
  csr_template: unknown;
  cname_map?: unknown;
}

export async function createDelegation(payload: DelegationCreatePayload): Promise<{ id: string }> {
  return apiJson(apiListPath('delegation'), {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function updateDelegation(id: string, payload: DelegationUpdatePayload): Promise<void> {
  const resp = await apiFetch(apiPath('delegation', id), {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function deleteDelegation(id: string): Promise<void> {
  const resp = await apiFetch(apiPath('delegation', id), { method: 'DELETE' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}
