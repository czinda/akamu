import { apiJson } from './client';
import { apiPath, apiListPath } from './paths';

export interface OrderRow {
  id: string;
  account_id: string;
  status: string;
  identifiers: string;
  created: number;
  updated: number;
  expires: number | null;
  certificate_id: string | null;
  profile: string | null;
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
  return apiJson(`${apiListPath('order')}?${qs}`);
}

export async function getOrder(id: string): Promise<OrderRow> {
  return apiJson(apiPath('order', id));
}
