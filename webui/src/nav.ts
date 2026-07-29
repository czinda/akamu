import type { Role } from './auth/AuthContext';
import { hasRole } from './auth/AuthContext';

export type RouteAccess =
  | 'public'
  | { minRole: Role }
  | { anyOf: Role[] };

export interface NavItem {
  path: string;
  label: string;
  access: RouteAccess;
  end?: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  { path: '/', label: 'Dashboard', access: 'public', end: true },
  { path: '/certs', label: 'Certificates', access: 'public' },
  { path: '/orders', label: 'Orders', access: 'public' },
  { path: '/accounts', label: 'Accounts', access: 'public' },
  { path: '/audit', label: 'Audit Log', access: { anyOf: ['administrator', 'auditor'] } },
  { path: '/eab', label: 'EAB Keys', access: { minRole: 'ca_ra' } },
  { path: '/delegations', label: 'Delegations', access: { minRole: 'ca_ra' } },
  { path: '/profiles', label: 'Profiles', access: { minRole: 'ca_ra' } },
  { path: '/cas', label: 'CAs', access: { minRole: 'ca_operations' } },
  { path: '/cross-certs', label: 'Cross-Certs', access: { anyOf: ['administrator', 'ca_operations', 'auditor'] } },
  { path: '/mtc', label: 'Transparency Log', access: { anyOf: ['administrator', 'ca_operations', 'auditor'] } },
  { path: '/policies', label: 'Policies', access: { anyOf: ['administrator', 'ca_operations', 'auditor'] } },
  { path: '/operators', label: 'Operators', access: { minRole: 'administrator' } },
  { path: '/config', label: 'Server Config', access: { minRole: 'administrator' } },
];

export function canAccess(role: Role | null, access: RouteAccess): boolean {
  if (access === 'public') return true;
  if ('minRole' in access) return hasRole(role, access.minRole);
  return role !== null && access.anyOf.includes(role);
}

export function accessForPath(path: string): RouteAccess {
  return NAV_ITEMS.find(item => item.path === path)?.access ?? { minRole: 'administrator' };
}
