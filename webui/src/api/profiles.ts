import { apiJson, apiFetch, ApiError } from './client';

export interface ProfileConfig {
  [key: string]: unknown;
}

export interface ProfileEntry {
  id: string;
  config: ProfileConfig;
}

export async function listProfiles(): Promise<{ providers: Record<string, unknown> }> {
  return apiJson('/admin/profiles');
}

export async function createProfile(id: string, params: ProfileConfig): Promise<void> {
  const resp = await apiFetch('/admin/profiles', {
    method: 'POST',
    body: JSON.stringify({ id, ...params }),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function updateProfile(id: string, params: ProfileConfig): Promise<void> {
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
