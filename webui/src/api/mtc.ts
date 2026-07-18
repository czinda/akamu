import { apiJson, apiFetch, apiVoid, ApiError, extractErrorMessage } from './client';

export interface MtcTreeSize {
  tree_size: number;
}

export interface MtcRoot {
  tree_size: number;
  root_hash: string;
}

export interface MtcLandmark {
  sequence_no: number;
  tree_size: number;
  created_at: number;
}

export interface MtcInclusionProof {
  leaf_index: number;
  tree_size: number;
  proof: { hash: string }[];
}

export interface MtcConsistencyProof {
  from_size: number;
  to_size: number;
  from_root: string;
  to_root: string;
}

export interface MtcSubtreeRoot {
  start: number;
  end: number;
  root_hash: string;
}

export interface MtcRevokedRange {
  start: number;
  end: number;
}

function caQuery(caId?: string): string {
  return caId ? `?ca_id=${encodeURIComponent(caId)}` : '';
}

async function fetchText(path: string): Promise<string> {
  const resp = await apiFetch(path);
  const text = await resp.text();
  if (!resp.ok) {
    throw new ApiError(resp.status, extractErrorMessage(resp.status, text, resp.statusText));
  }
  return text;
}

async function fetchBlob(path: string): Promise<Blob> {
  const resp = await apiFetch(path);
  if (!resp.ok) {
    let text: string;
    try {
      text = await resp.text();
    } catch {
      text = resp.statusText;
    }
    throw new ApiError(resp.status, extractErrorMessage(resp.status, text, resp.statusText));
  }
  return resp.blob();
}

// JSON endpoints

export async function getTreeSize(caId?: string): Promise<MtcTreeSize> {
  return apiJson(`/admin/mtc/tree-size${caQuery(caId)}`);
}

export async function getRoot(caId?: string): Promise<MtcRoot> {
  return apiJson(`/admin/mtc/root${caQuery(caId)}`);
}

export async function getLandmarks(caId?: string): Promise<MtcLandmark[]> {
  const resp: { landmarks: MtcLandmark[] } = await apiJson(`/admin/mtc/landmarks${caQuery(caId)}`);
  return resp.landmarks;
}

export async function getInclusionProof(certId: string): Promise<MtcInclusionProof> {
  return apiJson(`/admin/mtc/inclusion-proof/${encodeURIComponent(certId)}`);
}

export async function getConsistencyProof(
  caId: string,
  from: number,
  to: number,
): Promise<MtcConsistencyProof> {
  const params = new URLSearchParams({
    ca_id: caId,
    from: String(from),
    to: String(to),
  });
  return apiJson(`/admin/mtc/consistency-proof?${params}`);
}

export async function getSubtreeRoot(
  caId: string,
  start: number,
  end: number,
): Promise<MtcSubtreeRoot> {
  const params = new URLSearchParams({
    ca_id: caId,
    start: String(start),
    end: String(end),
  });
  return apiJson(`/admin/mtc/subtree-root?${params}`);
}

export async function getRevokedRanges(caId?: string): Promise<MtcRevokedRange[]> {
  const resp: { revoked_ranges: MtcRevokedRange[] } = await apiJson(`/admin/mtc/revoked-ranges${caQuery(caId)}`);
  return resp.revoked_ranges;
}

// Text endpoints

export async function getLandmarkList(caId?: string): Promise<string> {
  return fetchText(`/admin/mtc/landmark-list${caQuery(caId)}`);
}

export async function getCheckpoint(caId?: string): Promise<string> {
  return fetchText(`/admin/mtc/checkpoint${caQuery(caId)}`);
}

export async function getCosignature(caId?: string): Promise<string> {
  return fetchText(`/admin/mtc/cosignature${caQuery(caId)}`);
}

// Binary downloads

export async function downloadStandalone(certId: string): Promise<Blob> {
  return fetchBlob(`/admin/mtc/standalone/${encodeURIComponent(certId)}`);
}

export async function downloadLandmarkCert(seq: number, caId?: string): Promise<Blob> {
  return fetchBlob(`/admin/mtc/landmarks/${seq}/cert${caQuery(caId)}`);
}

export interface MtcLandmarkCertDetails {
  sequence_no: number;
  cert_text: string | null;
}

export async function getLandmarkCertDetails(
  seq: number,
  caId?: string,
): Promise<MtcLandmarkCertDetails> {
  return apiJson(`/admin/mtc/landmarks/${seq}/cert-details${caQuery(caId)}`);
}

export async function getLogListEntry(caId: string): Promise<string> {
  return fetchText(`/admin/ca/${encodeURIComponent(caId)}/mtc/log-list-entry`);
}

// Actions

export async function forceCheckpoint(caId: string): Promise<void> {
  return apiVoid(`/admin/ca/${encodeURIComponent(caId)}/mtc/force-checkpoint`, { method: 'POST' });
}

export async function forceLandmark(caId: string): Promise<void> {
  return apiVoid(`/admin/ca/${encodeURIComponent(caId)}/mtc/force-landmark`, { method: 'POST' });
}
