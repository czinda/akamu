/**
 * Format ACME identifiers JSON (stored as "[{type,value},…]") into a
 * readable comma-separated list, e.g. "dns:example.com, ip:192.0.2.1".
 * Falls back to the raw string on parse failure.
 */
export function fmtIdentifiers(raw: string | null | undefined): string {
  if (!raw) return '—';
  try {
    const arr = JSON.parse(raw) as Array<{ type?: string; value?: string }>;
    if (Array.isArray(arr)) {
      return arr.map(id => `${id.type ?? '?'}:${id.value ?? '?'}`).join(', ') || '—';
    }
  } catch {
    // not valid JSON — return as-is
  }
  return raw;
}

/** Format a Unix epoch (seconds) as a local date-time string, or '—' if null/undefined/zero. */
export function fmtTs(ts: number | null | undefined): string {
  if (ts == null || ts === 0) return '—';
  return new Date(ts * 1000).toLocaleString();
}

/** Trigger a browser download from an in-memory Blob. */
export function triggerBlobDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** Format an ISO 8601 date string as a local date-time string, or '—' if null/undefined. */
export function fmtIso(s: string | null | undefined): string {
  if (!s) return '—';
  return new Date(s).toLocaleString();
}

/** All navigable object types and their canonical list-page path segments. */
export type ObjType =
  | 'account'
  | 'ca'
  | 'cert'
  | 'cross-cert'
  | 'delegation'
  | 'eab'
  | 'operator'
  | 'order'
  | 'profile';

/** Return the canonical detail-page path for an object. Single source of truth for URLs. */
export function objectPath(type: ObjType, id: string): string {
  switch (type) {
    case 'account':    return `/accounts/${id}`;
    case 'ca':         return `/cas/${id}`;
    case 'cert':       return `/certs/${id}`;
    case 'cross-cert': return `/cross-certs/${id}`;
    case 'delegation': return `/delegations/${id}`;
    case 'eab':        return `/eab/${id}`;
    case 'operator':   return `/operators/${id}`;
    case 'order':      return `/orders/${id}`;
    case 'profile':    return `/profiles/${id}`;
  }
}

/**
 * Infer the detail-page path for an audit event's subject field.
 * Returns null when the subject type cannot be determined (e.g. cert serial,
 * authz ID) or when the event type has no navigable subject.
 */
export function auditSubjectPath(eventType: string, subject: string): string | null {
  if (eventType.startsWith('account.')) return objectPath('account', subject);
  if (eventType.startsWith('order.'))   return objectPath('order', subject);
  if (eventType === 'eab.use' || eventType === 'eab.reject') return objectPath('eab', subject);
  // cert.issue/cert.revoke subjects are serial-hex strings, not UUIDs — cannot link directly.
  return null;
}
