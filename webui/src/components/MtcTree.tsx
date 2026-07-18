import { useState, useRef, useEffect, useCallback } from 'react';
import {
  Button,
  TextInput,
  Alert,
  Spinner,
} from '@patternfly/react-core';
import {
  getInclusionProof,
  type MtcRoot,
  type MtcLandmark,
  type MtcRevokedRange,
  type MtcInclusionProof,
} from '../api/mtc';

interface MtcTreeProps {
  root: MtcRoot;
  landmarks: MtcLandmark[];
  revokedRanges: MtcRevokedRange[];
  checkpoint: string | null;  // C2SP signed-note text; line 2 is tree_size
}

// C2SP signed-note: line 0 = origin, line 1 = tree_size, line 2 = base64(root)
function parseCheckpointSize(note: string): number | null {
  const lines = note.trim().split('\n');
  if (lines.length < 2) return null;
  const n = parseInt(lines[1], 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

const SVG_HEIGHT = 200;
const BAR_Y = 110;
const BAR_H = 24;
const TICK_TOP = BAR_Y - 16;
const TICK_BOT = BAR_Y + BAR_H;
const ROOT_Y = 12;
const ROOT_H = 28;
const ROOT_W = 220;
const LABEL_STEP_THRESHOLD = 8; // only label every N-th landmark when crowded

function abbrev(hash: string): string {
  return hash.length > 16 ? `${hash.slice(0, 8)}…${hash.slice(-8)}` : hash;
}

export default function MtcTree({ root, landmarks, revokedRanges, checkpoint }: MtcTreeProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [barWidth, setBarWidth] = useState(700);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w && w > 100) setBarWidth(Math.floor(w) - 2);
    });
    obs.observe(el);
    setBarWidth(Math.max(300, el.clientWidth - 2));
    return () => obs.disconnect();
  }, []);

  const [certId, setCertId] = useState('');
  const [proof, setProof] = useState<MtcInclusionProof | null>(null);
  const [proofError, setProofError] = useState<string | null>(null);
  const [proofLoading, setProofLoading] = useState(false);
  const proofRequestId = useRef(0);

  const handleShowProof = useCallback(async () => {
    const id = certId.trim();
    if (!id) return;
    const requestId = ++proofRequestId.current;
    setProofLoading(true);
    setProofError(null);
    setProof(null);
    try {
      const result = await getInclusionProof(id);
      if (proofRequestId.current !== requestId) return;
      setProof(result);
    } catch (e: unknown) {
      if (proofRequestId.current !== requestId) return;
      setProofError(e instanceof Error ? e.message : 'Failed to fetch proof');
    } finally {
      if (proofRequestId.current === requestId) setProofLoading(false);
    }
  }, [certId]);

  const { tree_size: treeSize, root_hash: rootHash } = root;

  const svgCx = barWidth / 2;
  const barX = 0;

  function toX(leafIndex: number, scale = treeSize): number {
    if (scale === 0) return barX;
    return barX + (leafIndex / scale) * barWidth;
  }

  const lastLandmarkSize = landmarks.length > 0
    ? landmarks[landmarks.length - 1].tree_size
    : 0;
  const landmarkEndX = treeSize > 0 ? toX(lastLandmarkSize) : 0;
  const fullyLandmarked = treeSize > 0 && lastLandmarkSize >= treeSize;

  const cpSize = checkpoint ? parseCheckpointSize(checkpoint) : null;

  const labelStep = landmarks.length > LABEL_STEP_THRESHOLD
    ? Math.ceil(landmarks.length / LABEL_STEP_THRESHOLD)
    : 1;

  // SVG total height: base + proof chain rows
  const proofRows = proof ? proof.proof.length + 2 : 0; // +2 for leaf and root rows
  const svgH = SVG_HEIGHT + proofRows * 22;

  // proof leaf x position — use proof.tree_size as the scale, not current treeSize
  const proofLeafX = proof && proof.tree_size > 0
    ? toX(proof.leaf_index, proof.tree_size)
    : null;

  return (
    <div>
      <div ref={containerRef} style={{ width: '100%', overflowX: 'auto' }}>
        <svg
          width={barWidth}
          height={svgH}
          role="img"
          aria-label="MTC log timeline"
          style={{ display: 'block' }}
        >
          {/* Root badge */}
          <rect
            x={svgCx - ROOT_W / 2}
            y={ROOT_Y}
            width={ROOT_W}
            height={ROOT_H}
            rx={5}
            fill="var(--pf-t--global--color--brand--default, #0066cc)"
          />
          <text
            x={svgCx}
            y={ROOT_Y + 11}
            textAnchor="middle"
            fontSize={10}
            fill="white"
            fontFamily="var(--pf-t--global--font--family--mono, monospace)"
          >
            {abbrev(rootHash)}
          </text>
          <text
            x={svgCx}
            y={ROOT_Y + 23}
            textAnchor="middle"
            fontSize={10}
            fill="white"
          >
            size: {treeSize}
          </text>

          {/* Line from root badge to timeline bar */}
          <line
            x1={svgCx}
            y1={ROOT_Y + ROOT_H}
            x2={svgCx}
            y2={BAR_Y}
            stroke="var(--pf-t--global--color--brand--default, #0066cc)"
            strokeWidth={1.5}
          />

          {treeSize === 0 ? (
            <text x={svgCx} y={BAR_Y + 40} textAnchor="middle" fontSize={12}
              fill="var(--pf-t--global--color--nonstatus--gray--default, #666)">
              No leaves yet
            </text>
          ) : (
            <>
              {/* Landmarked portion (green) */}
              {lastLandmarkSize > 0 && (
                <rect
                  x={barX}
                  y={BAR_Y}
                  width={landmarkEndX}
                  height={BAR_H}
                  fill="var(--pf-t--global--color--status--success--default, #3e8635)"
                />
              )}

              {/* Active (un-landmarked) portion (orange), or "fully landmarked" label */}
              {fullyLandmarked ? (
                <text
                  x={barWidth}
                  y={BAR_Y + BAR_H + 24}
                  textAnchor="end"
                  fontSize={9}
                  fill="var(--pf-t--global--color--status--success--default, #3e8635)"
                >
                  All leaves landmarked (LM#{landmarks[landmarks.length - 1].sequence_no})
                </text>
              ) : (
                <rect
                  x={landmarkEndX}
                  y={BAR_Y}
                  width={barWidth - landmarkEndX}
                  height={BAR_H}
                  fill="var(--pf-t--global--color--status--warning--default, #f0ab00)"
                />
              )}

              {/* Checkpoint tick (CP) — taller blue marker, distinct from landmark ticks */}
              {cpSize !== null && treeSize > 0 && (
                <g>
                  <line
                    x1={toX(cpSize)}
                    y1={BAR_Y - 26}
                    x2={toX(cpSize)}
                    y2={BAR_Y + BAR_H}
                    stroke="var(--pf-t--global--color--brand--default, #0066cc)"
                    strokeWidth={2}
                  />
                  <text
                    x={toX(cpSize)}
                    y={BAR_Y - 28}
                    textAnchor="middle"
                    fontSize={9}
                    fontWeight="bold"
                    fill="var(--pf-t--global--color--brand--default, #0066cc)"
                  >
                    CP
                  </text>
                  <text
                    x={toX(cpSize)}
                    y={BAR_Y + BAR_H + 12}
                    textAnchor="middle"
                    fontSize={9}
                    fill="var(--pf-t--global--color--brand--default, #0066cc)"
                  >
                    {cpSize}
                  </text>
                </g>
              )}

              {/* Revoked range overlays */}
              {revokedRanges.map((r) => {
                const naturalX = toX(r.start);
                const naturalW = toX(r.end) - naturalX;
                const MIN_W = 8;
                const displayW = Math.max(MIN_W, naturalW);
                // Center the expanded rect on the natural position so a single-leaf
                // range is visible rather than collapsing to a 0-width sliver.
                const displayX = naturalX - (displayW - naturalW) / 2;
                return (
                  <rect
                    key={`rev-${r.start}-${r.end}`}
                    x={displayX}
                    y={BAR_Y}
                    width={displayW}
                    height={BAR_H}
                    fill="var(--pf-t--global--color--status--danger--default, #c9190b)"
                  />
                );
              })}

              {/* Landmark tick marks */}
              {landmarks.map((lm, i) => {
                const lx = toX(lm.tree_size);
                const showLabel = i % labelStep === 0;
                return (
                  <g key={`lm-${lm.sequence_no}`}>
                    <line
                      x1={lx}
                      y1={TICK_TOP}
                      x2={lx}
                      y2={TICK_BOT}
                      stroke="var(--pf-t--global--border--color--default, #8a8d90)"
                      strokeWidth={1}
                    />
                    {showLabel && (
                      <>
                        <text
                          x={lx}
                          y={TICK_TOP - 2}
                          textAnchor="middle"
                          fontSize={9}
                          fill="var(--pf-t--global--text--color--subtle, #6a6e73)"
                        >
                          LM#{lm.sequence_no}
                        </text>
                        <text
                          x={lx}
                          y={TICK_BOT + 12}
                          textAnchor="middle"
                          fontSize={9}
                          fill="var(--pf-t--global--text--color--subtle, #6a6e73)"
                        >
                          {lm.tree_size}
                        </text>
                      </>
                    )}
                  </g>
                );
              })}

              {/* Bar end label */}
              <text
                x={barWidth - 2}
                y={BAR_Y + BAR_H + 12}
                textAnchor="end"
                fontSize={9}
                fill="var(--pf-t--global--text--color--subtle, #6a6e73)"
              >
                {treeSize}
              </text>

              {/* Proof leaf marker */}
              {proofLeafX !== null && (
                <>
                  <line
                    x1={proofLeafX}
                    y1={ROOT_Y + ROOT_H}
                    x2={proofLeafX}
                    y2={BAR_Y + BAR_H / 2}
                    stroke="var(--pf-t--global--color--status--info--default, #009596)"
                    strokeWidth={1.5}
                    strokeDasharray="4 3"
                  />
                  <circle
                    cx={proofLeafX}
                    cy={BAR_Y + BAR_H / 2}
                    r={5}
                    fill="var(--pf-t--global--color--status--info--default, #009596)"
                  />
                  <text
                    x={proofLeafX}
                    y={BAR_Y + BAR_H + 24}
                    textAnchor="middle"
                    fontSize={9}
                    fill="var(--pf-t--global--color--status--info--default, #009596)"
                  >
                    leaf #{proof?.leaf_index}
                  </text>
                </>
              )}

              {/* Proof node chain */}
              {proof && (
                <>
                  {/* Column header */}
                  <text
                    x={4}
                    y={SVG_HEIGHT + 10}
                    fontSize={10}
                    fill="var(--pf-t--global--text--color--subtle, #6a6e73)"
                    fontStyle="italic"
                  >
                    Inclusion proof path ({proof.proof.length} sibling{proof.proof.length !== 1 ? 's' : ''}):
                  </text>
                  {proof.proof.map((node, idx) => (
                    <text
                      key={`ph-${idx}`}
                      x={4}
                      y={SVG_HEIGHT + 28 + idx * 22}
                      fontSize={10}
                      fontFamily="var(--pf-t--global--font--family--mono, monospace)"
                      fill="var(--pf-t--global--text--color--regular, #151515)"
                    >
                      [{idx}] {abbrev(node.hash)}
                    </text>
                  ))}
                  <text
                    x={4}
                    y={SVG_HEIGHT + 28 + proof.proof.length * 22}
                    fontSize={10}
                    fontFamily="var(--pf-t--global--font--family--mono, monospace)"
                    fill="var(--pf-t--global--color--brand--default, #0066cc)"
                  >
                    root: {abbrev(proof.tree_size === treeSize ? rootHash : '(different tree size)')}
                  </text>
                </>
              )}
            </>
          )}
        </svg>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem', fontSize: '0.8rem',
        color: 'var(--pf-t--global--text--color--subtle, #6a6e73)' }}>
        <span>
          <svg width={12} height={12} style={{ verticalAlign: 'middle', marginRight: 4 }}>
            <rect width={12} height={12} rx={2}
              fill="var(--pf-t--global--color--status--success--default, #3e8635)" />
          </svg>
          Landmarked
        </span>
        <span>
          <svg width={12} height={12} style={{ verticalAlign: 'middle', marginRight: 4 }}>
            <rect width={12} height={12} rx={2}
              fill="var(--pf-t--global--color--status--warning--default, #f0ab00)" />
          </svg>
          Active
        </span>
        <span>
          <svg width={12} height={12} style={{ verticalAlign: 'middle', marginRight: 4 }}>
            <rect width={12} height={12} rx={2}
              fill="var(--pf-t--global--color--status--danger--default, #c9190b)"
              opacity={0.7} />
          </svg>
          Revoked
        </span>
        <span>
          <svg width={12} height={12} style={{ verticalAlign: 'middle', marginRight: 4 }}>
            <circle cx={6} cy={6} r={5}
              fill="var(--pf-t--global--color--status--info--default, #009596)" />
          </svg>
          Proof leaf
        </span>
        <span>
          <svg width={12} height={12} style={{ verticalAlign: 'middle', marginRight: 4 }}>
            <line x1={6} y1={0} x2={6} y2={12}
              stroke="var(--pf-t--global--color--brand--default, #0066cc)" strokeWidth={2} />
          </svg>
          Checkpoint
        </span>
      </div>

      {/* Proof explorer */}
      <div style={{ marginTop: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-end' }}>
          <div style={{ flex: 1, maxWidth: 420 }}>
            <label htmlFor="mtc-proof-cert-id"
              style={{ display: 'block', fontSize: '0.85rem', marginBottom: '0.25rem' }}>
              Certificate UUID
            </label>
            <TextInput
              id="mtc-proof-cert-id"
              value={certId}
              onChange={(_e, v) => setCertId(v)}
              placeholder="Enter cert UUID to show inclusion proof"
              onKeyDown={(e) => { if (e.key === 'Enter') handleShowProof(); }}
            />
          </div>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleShowProof}
            isLoading={proofLoading}
            isDisabled={proofLoading || !certId.trim()}
          >
            Show Proof
          </Button>
          {proof && (
            <Button variant="plain" size="sm" onClick={() => { setProof(null); setProofError(null); }}>
              Clear
            </Button>
          )}
        </div>
        {proofLoading && <Spinner size="sm" style={{ marginTop: '0.5rem' }} />}
        {proofError && (
          <Alert variant="warning" title={proofError} isInline style={{ marginTop: '0.5rem' }} />
        )}
        {proof && (
          <div style={{ marginTop: '0.5rem', fontSize: '0.85rem',
            color: 'var(--pf-t--global--text--color--subtle, #6a6e73)' }}>
            Leaf index <strong>{proof.leaf_index}</strong> of <strong>{proof.tree_size}</strong> leaves
            &nbsp;·&nbsp; {proof.proof.length} sibling hash{proof.proof.length !== 1 ? 'es' : ''}
          </div>
        )}
      </div>
    </div>
  );
}
