import { apiJson } from './client';

export interface OrderRow {
  id: string;
  account_id: string;
  status: string;
  identifiers: string;
  created_at: string;
  expires_at: string | null;
  cert_id: string | null;
  ca_id: string;
}

export interface OrderListParams {
  account_id?: string;
  status?: string;
  ca_id?: string;
  limit?: number;
  offset?: number;
}

export async function listOrders(params: OrderListParams = {}): Promise<{ orders: OrderRow[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.account_id) qs.set('account_id', params.account_id);
  if (params.status) qs.set('status', params.status);
  if (params.ca_id) qs.set('ca_id', params.ca_id);
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return apiJson(`/admin/orders?${qs}`);
}

export async function getOrder(id: string): Promise<OrderRow> {
  return apiJson(`/admin/orders/${id}`);
}
