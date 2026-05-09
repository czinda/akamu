import { apiJson, apiFetch, ApiError } from './client';

export interface ProfileEntry {
  id: string;
  description: string;
  validity_days?: number;
  hash_alg?: string;
  extended_key_usages?: string[];
}

export async function listProfiles(): Promise<{ profiles: ProfileEntry[] }> {
  return apiJson('/admin/profiles');
}

export async function createProfile(id: string, params: Record<string, unknown>): Promise<void> {
  const resp = await apiFetch('/admin/profiles', {
    method: 'POST',
    body: JSON.stringify({ id, ...params }),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function updateProfile(id: string, params: Record<string, unknown>): Promise<void> {
  const resp = await apiFetch(`/admin/profiles/${id}`, {
    method: 'PUT',
    body: JSON.stringify(params),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function deleteProfile(id: string): Promise<void> {
  const resp = await apiFetch(`/admin/profiles/${id}`, { method: 'DELETE' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}
