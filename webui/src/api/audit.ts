import { apiJson } from './client';

export interface AuditEntry {
  id: string;
  ts: string;
  operator_id: string | null;
  operator_name: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  detail: string | null;
  outcome: string;
}

export interface AuditQueryParams {
  operator_id?: string;
  action?: string;
  target_type?: string;
  target_id?: string;
  outcome?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

export async function queryAudit(params: AuditQueryParams = {}): Promise<{ entries: AuditEntry[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.operator_id) qs.set('operator_id', params.operator_id);
  if (params.action) qs.set('action', params.action);
  if (params.target_type) qs.set('target_type', params.target_type);
  if (params.target_id) qs.set('target_id', params.target_id);
  if (params.outcome) qs.set('outcome', params.outcome);
  if (params.from) qs.set('from', params.from);
  if (params.to) qs.set('to', params.to);
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return apiJson(`/admin/audit?${qs}`);
}
