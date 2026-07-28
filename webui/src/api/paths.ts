/**
 * Single source of truth for server-side API URL construction.
 *
 * The server is inconsistent: some resources use a singular prefix for detail
 * and action routes even though the list route is plural (e.g. `account` vs
 * `accounts`, `ca` vs `cas`).  All of that is encapsulated here so the rest of
 * the client never has to think about it.
 */
import type { ObjType } from '../utils';
export type { ObjType };

/** Canonical path for GET / PUT / DELETE on a single resource. */
export function apiPath(type: ObjType, id: string): string {
  switch (type) {
    case 'account':    return `/admin/account/${id}`;      // server uses singular
    case 'ca':         return `/admin/cas/${id}`;
    case 'cert':       return `/admin/certs/${id}`;
    case 'cross-cert': return `/admin/cross-certs/${id}`;
    case 'delegation': return `/admin/delegations/${id}`;
    case 'eab':        return `/admin/eab/${id}`;
    case 'operator':   return `/admin/operators/${id}`;
    case 'order':      return `/admin/orders/${id}`;
    case 'policy':     return `/admin/policy/rules/${id}`;
    case 'profile':    return `/admin/profiles/${id}`;
  }
}

/**
 * Canonical path for POST actions on a resource.
 * `account` and `ca` use a singular prefix for actions that differs from their
 * detail path; all other types extend their detail path directly.
 */
export function apiActionPath(type: ObjType, id: string, action: string): string {
  switch (type) {
    case 'account': return `/admin/account/${id}/${action}`;
    case 'ca':      return `/admin/ca/${id}/${action}`;
    default:        return `${apiPath(type, id)}/${action}`;
  }
}

/** Canonical path for list (GET) and create (POST) operations. */
export function apiListPath(type: ObjType): string {
  switch (type) {
    case 'account':    return '/admin/accounts';
    case 'ca':         return '/admin/cas';
    case 'cert':       return '/admin/certs';
    case 'cross-cert': return '/admin/cross-certs';
    case 'delegation': return '/admin/delegations';
    case 'eab':        return '/admin/eab';
    case 'operator':   return '/admin/operators';
    case 'order':      return '/admin/orders';
    case 'policy':     return '/admin/policy/rules';
    case 'profile':    return '/admin/profiles';
  }
}
