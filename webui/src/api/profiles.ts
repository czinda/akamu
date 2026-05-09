import { apiJson, apiFetch, ApiError } from './client';
import { apiPath, apiListPath } from './paths';

export interface CertificatePolicy {
  oid: string;
  cps_uri: string | null;
}

export interface ProfileEntry {
  id: string;
  description: string;
  validity_days?: number;
  hash_alg?: string;
  key_usage_bits?: number;
  extended_key_usages?: string[];
  crl_url?: string | null;
  ocsp_url?: string | null;
  allowed_key_types?: string[];
  certificate_policies?: [string, string | null][];
  issue_as_mtc?: boolean;
  allowed_identifier_patterns?: string[];
  identifier_match_all?: boolean;
  auth_hook?: string | null;
  auth_hook_timeout_secs?: number;
  require_account_grant?: boolean;
  ca_ids?: string[];
}

export async function listProfiles(): Promise<{ profiles: ProfileEntry[] }> {
  return apiJson(apiListPath('profile'));
}

export async function getProfile(id: string): Promise<ProfileEntry> {
  return apiJson(apiPath('profile', id));
}

export interface ProfilePayload {
  description: string;
  validity_days: number;
  hash_alg: string;
  key_usage_bits: number;
  extended_key_usages: string[];
  crl_url: string | null;
  ocsp_url: string | null;
  allowed_key_types: string[];
  certificate_policies: [string, string | null][];
  issue_as_mtc: boolean;
  allowed_identifier_patterns: string[];
  identifier_match_all: boolean;
  auth_hook: string | null;
  auth_hook_timeout_secs: number;
  require_account_grant: boolean;
  ca_ids: string[];
}

export async function createProfile(id: string, payload: ProfilePayload): Promise<void> {
  const resp = await apiFetch(apiListPath('profile'), {
    method: 'POST',
    body: JSON.stringify({ id, ...payload }),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function updateProfile(id: string, payload: ProfilePayload): Promise<void> {
  const resp = await apiFetch(apiPath('profile', id), {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function deleteProfile(id: string): Promise<void> {
  const resp = await apiFetch(apiPath('profile', id), { method: 'DELETE' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}
