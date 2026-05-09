import { apiJson, apiFetch, ApiError } from './client';
import { apiPath, apiActionPath, apiListPath } from './paths';

export interface OperatorRow {
  id: string;
  name: string;
  role: string;
  ca_id: string | null;
  cert_fingerprint: string | null;
  gssapi_principal: string | null;
  active: boolean;
  locked: boolean;
  failed_attempts: number;
  locked_until: string | null;
  created_at: string;
  last_seen_at: string | null;
}

export interface CreateOperatorOptions {
  name: string;
  role: string;
  cert_fingerprint?: string;
  gssapi_principal?: string;
  ca_id?: string;
}

export interface UpdateOperatorOptions {
  name?: string;
  role?: string;
  cert_fingerprint?: string;
  gssapi_principal?: string;
  ca_id?: string;
}

export async function listOperators(): Promise<{ operators: OperatorRow[] }> {
  return apiJson(apiListPath('operator'));
}

export async function getOperator(id: string): Promise<OperatorRow> {
  return apiJson(apiPath('operator', id));
}

export async function createOperator(opts: CreateOperatorOptions): Promise<{ id: string }> {
  return apiJson(apiListPath('operator'), {
    method: 'POST',
    body: JSON.stringify(opts),
  });
}

export async function updateOperator(id: string, opts: UpdateOperatorOptions): Promise<void> {
  const resp = await apiFetch(apiPath('operator', id), {
    method: 'PUT',
    body: JSON.stringify(opts),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function activateOperator(id: string): Promise<void> {
  const resp = await apiFetch(apiPath('operator', id), {
    method: 'PATCH',
    body: JSON.stringify({ active: true }),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function deactivateOperator(id: string): Promise<void> {
  const resp = await apiFetch(apiPath('operator', id), {
    method: 'PATCH',
    body: JSON.stringify({ active: false }),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function unlockOperator(id: string): Promise<void> {
  const resp = await apiFetch(apiActionPath('operator', id, 'unlock'), { method: 'POST' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}
