import { apiJson } from './client';

export interface AuditEntry {
  id: string;
  occurred_at: string;
  event_type: string;
  subject: string | null;
  principal: string | null;
  outcome: string;
  detail: string | null;
}

export interface AuditQueryParams {
  type?: string;
  subject?: string;
  outcome?: string;
  from?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

export async function queryAudit(params: AuditQueryParams = {}): Promise<{ events: AuditEntry[]; limit: number; offset: number }> {
  const qs = new URLSearchParams();
  if (params.type) qs.set('type', params.type);
  if (params.subject) qs.set('subject', params.subject);
  if (params.outcome) qs.set('outcome', params.outcome);
  if (params.from) qs.set('from', params.from);
  if (params.until) qs.set('until', params.until);
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return apiJson(`/admin/audit?${qs}`);
}
