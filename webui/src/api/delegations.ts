import { apiJson, apiFetch, ApiError } from './client';

export interface DelegationRow {
  id: string;
  account_id: string;
  csr_template: string;
  cname_map: string | null;
  created_at: string;
}

export interface DelegationListParams {
  account_id?: string;
  limit?: number;
  offset?: number;
}

export async function listDelegations(params: DelegationListParams = {}): Promise<{ delegations: DelegationRow[] }> {
  const qs = new URLSearchParams();
  if (params.account_id) qs.set('account_id', params.account_id);
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return apiJson(`/admin/delegations?${qs}`);
}

export async function getDelegation(id: string): Promise<DelegationRow> {
  return apiJson(`/admin/delegations/${id}`);
}

export interface DelegationOptions {
  account_id: string;
  csr_template: string;
  cname_map?: Record<string, string>;
}

export async function createDelegation(opts: DelegationOptions): Promise<{ id: string }> {
  return apiJson('/admin/delegations', {
    method: 'POST',
    body: JSON.stringify(opts),
  });
}

export async function updateDelegation(id: string, opts: Partial<DelegationOptions>): Promise<void> {
  const resp = await apiFetch(`/admin/delegations/${id}`, {
    method: 'PUT',
    body: JSON.stringify(opts),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function deleteDelegation(id: string): Promise<void> {
  const resp = await apiFetch(`/admin/delegations/${id}`, { method: 'DELETE' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}
