import { apiJson } from './client';

export interface ServerStats {
  certificates_total: number;
  certificates_valid: number;
  certificates_revoked: number;
  certificates_expired: number;
  orders_pending: number;
  orders_ready: number;
  orders_processing: number;
  orders_valid: number;
  orders_invalid: number;
  accounts_active: number;
  accounts_deactivated: number;
  accounts_revoked: number;
}

export interface ServerConfig {
  [key: string]: unknown;
}

export async function getStats(): Promise<ServerStats> {
  return apiJson('/admin/stats');
}

export async function getConfig(): Promise<ServerConfig> {
  return apiJson('/admin/config');
}
