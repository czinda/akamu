import { apiJson, apiFetch, ApiError } from './client';

export interface AccountRow {
  id: string;
  status: string;
  created_at: string;
  last_seen_at: string | null;
  profile_grants: string[] | null;
  ca_id: string;
}

export interface AccountListParams {
  status?: string;
  ca_id?: string;
  limit?: number;
  offset?: number;
}

export async function listAccounts(params: AccountListParams = {}): Promise<{ accounts: AccountRow[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.status) qs.set('status', params.status);
  if (params.ca_id) qs.set('ca_id', params.ca_id);
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return apiJson(`/admin/accounts?${qs}`);
}

export async function getAccount(id: string): Promise<AccountRow> {
  return apiJson(`/admin/accounts/${id}`);
}

export async function deactivateAccount(id: string): Promise<void> {
  const resp = await apiFetch(`/admin/accounts/${id}/deactivate`, { method: 'POST' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function getGrants(id: string): Promise<{ profile_grants: string[] | null }> {
  return apiJson(`/admin/account/${id}/profile-grants`);
}

export async function setGrants(id: string, grants: string[]): Promise<void> {
  const resp = await apiFetch(`/admin/account/${id}/profile-grants`, {
    method: 'PUT',
    body: JSON.stringify({ profile_grants: grants }),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function clearGrants(id: string): Promise<void> {
  const resp = await apiFetch(`/admin/account/${id}/profile-grants`, { method: 'DELETE' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}
