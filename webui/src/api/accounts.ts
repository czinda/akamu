import { apiJson, apiFetch, ApiError } from './client';
import { apiPath, apiActionPath, apiListPath } from './paths';

export interface AccountRow {
  id: string;
  status: string;
  contact: string | null;
  jwk_thumbprint: string;
  created: number;
  updated: number;
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
  return apiJson(`${apiListPath('account')}?${qs}`);
}

export async function getAccount(id: string): Promise<AccountRow> {
  return apiJson(apiPath('account', id));
}

export async function deactivateAccount(id: string): Promise<void> {
  const resp = await apiFetch(apiActionPath('account', id, 'deactivate'), { method: 'POST' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function getGrants(id: string): Promise<{ profile_grants: string[] | null }> {
  return apiJson(apiActionPath('account', id, 'profile-grants'));
}

export async function setGrants(id: string, grants: string[]): Promise<void> {
  const resp = await apiFetch(apiActionPath('account', id, 'profile-grants'), {
    method: 'PUT',
    body: JSON.stringify({ profile_grants: grants }),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function clearGrants(id: string): Promise<void> {
  const resp = await apiFetch(apiActionPath('account', id, 'profile-grants'), { method: 'DELETE' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}
