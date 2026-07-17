import { apiJson } from './client';

export interface ServerStats {
  server_version: string;
  uptime_secs: number;
  ca_scope: string | null;
  accounts: {
    total: number;
    active: number;
  };
  certs: {
    total: number;
    active: number;
    revoked: number;
  };
  eab_keys: {
    total: number;
    used: number;
    bound: number;
    free: number;
  };
  audit_events: {
    since_startup: number;
    journal_connected: boolean;
  };
  mtc: {
    ca_id: string;
    enabled: boolean;
    tree_size: number | null;
    landmarks: number | null;
    last_checkpoint_at: number;
    last_landmark_at: number;
    cosigner_count: number;
  }[];
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
