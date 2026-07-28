import { apiJson, apiVoid, apiDelete } from './client';

const POLICY_BASE = '/admin/policy';

export interface PolicyRule {
  id: string;
  scope: string;
  name: string;
  rule_json: Record<string, unknown>;
  enabled: boolean;
  corrupt?: boolean;
  created_at: string;
  updated_at: string;
  created_by: string | null;
}

export interface CreatePolicyRulePayload {
  scope: string;
  name: string;
  rule: Record<string, unknown>;
  enabled: boolean;
}

export interface UpdatePolicyRulePayload {
  name: string;
  rule: Record<string, unknown>;
  enabled: boolean;
}

export async function listScopes(): Promise<string[]> {
  return apiJson(`${POLICY_BASE}/scopes`);
}

export async function listRules(scope: string): Promise<PolicyRule[]> {
  return apiJson(`${POLICY_BASE}/rules?scope=${encodeURIComponent(scope)}`);
}

export async function createRule(
  payload: CreatePolicyRulePayload,
): Promise<{ id: string; name: string }> {
  return apiJson(`${POLICY_BASE}/rules`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function updateRule(
  id: string,
  payload: UpdatePolicyRulePayload,
): Promise<void> {
  return apiVoid(`${POLICY_BASE}/rules/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}

export async function deleteRule(id: string): Promise<void> {
  return apiDelete(`${POLICY_BASE}/rules/${encodeURIComponent(id)}`);
}
