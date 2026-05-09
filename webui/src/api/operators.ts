import { apiJson, apiFetch, ApiError } from './client';

export interface OperatorRow {
  id: string;
  name: string;
  role: string;
  active: boolean;
  locked: boolean;
  created_at: string;
  last_seen_at: string | null;
}

export interface CreateOperatorOptions {
  name: string;
  role: string;
}

export interface UpdateOperatorOptions {
  role?: string;
}

export async function listOperators(): Promise<{ operators: OperatorRow[] }> {
  return apiJson('/admin/operators');
}

export async function getOperator(id: string): Promise<OperatorRow> {
  return apiJson(`/admin/operators/${id}`);
}

export async function createOperator(opts: CreateOperatorOptions): Promise<{ id: string }> {
  return apiJson('/admin/operators', {
    method: 'POST',
    body: JSON.stringify(opts),
  });
}

export async function updateOperator(id: string, opts: UpdateOperatorOptions): Promise<void> {
  const resp = await apiFetch(`/admin/operators/${id}`, {
    method: 'PUT',
    body: JSON.stringify(opts),
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function activateOperator(id: string): Promise<void> {
  const resp = await apiFetch(`/admin/operators/${id}/activate`, { method: 'POST' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function deactivateOperator(id: string): Promise<void> {
  const resp = await apiFetch(`/admin/operators/${id}/deactivate`, { method: 'POST' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}

export async function unlockOperator(id: string): Promise<void> {
  const resp = await apiFetch(`/admin/operators/${id}/unlock`, { method: 'POST' });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
}
