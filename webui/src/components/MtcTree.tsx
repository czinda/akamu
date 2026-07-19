import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
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
  checkpoint: string | null;
}

function parseCheckpointSize(note: string): number | null {
  const lines = note.trim().split('\n');
  if (lines.length < 2) return null;
  const n = parseInt(lines[1], 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

const BAR_H = 24;
const ROOT_Y = 12;
const ROOT_H = 28;
const ROOT_W = 220;
const RANGE_LABEL_W = 64;
const ROW_SPACING = 56;
const FIRST_ROW_Y = 80;
const TICK_ABOVE = 16;
const TICK_BELOW = 0;
const LABEL_STEP_THRESHOLD = 8;

function abbrev(hash: string): string {
  return hash.length > 16 ? `${hash.slice(0, 8)}…${hash.slice(-8)}` : hash;
}

function computeInitialLeavesPerRow(treeSize: number): number {
  if (treeSize <= 1000) return Math.max(treeSize, 1);
  const target = Math.ceil(treeSize / 4);
  const magnitude = Math.pow(10, Math.floor(Math.log10(target)));
  return Math.ceil(target / magnitude) * magnitude;
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

  const [leavesPerRow, setLeavesPerRow] = useState(() => computeInitialLeavesPerRow(treeSize));

  useEffect(() => {
    setLeavesPerRow(computeInitialLeavesPerRow(treeSize));
  }, [treeSize]);

  const numRows = treeSize > 0 ? Math.ceil(treeSize / leavesPerRow) : 1;
  const effectiveBarWidth = barWidth - RANGE_LABEL_W;
  const svgCx = barWidth / 2;

  function toRowX(leafIndex: number, rowStart: number): number {
    return RANGE_LABEL_W + ((leafIndex - rowStart) / leavesPerRow) * effectiveBarWidth;
  }

  function rowY(row: number): number {
    return FIRST_ROW_Y + row * ROW_SPACING;
  }

  const lastLandmarkSize = landmarks.length > 0
    ? landmarks[landmarks.length - 1].tree_size
    : 0;

  const cpSize = checkpoint ? parseCheckpointSize(checkpoint) : null;

  const proofRows = proof ? proof.proof.length + 2 : 0;
  const lastRowBottom = rowY(numRows - 1) + BAR_H + 20;
  const svgH = lastRowBottom + proofRows * 22 + 20;

  const zoomMin = Math.max(100, Math.ceil(treeSize / 20));
  const zoomMax = Math.max(treeSize, 1);

  function handleZoomIn() {
    setLeavesPerRow((prev) => {
      const next = Math.ceil(prev / 2);
      return Math.max(next, zoomMin);
    });
  }

  function handleZoomOut() {
    setLeavesPerRow((prev) => {
      const next = prev * 2;
      return Math.min(next, zoomMax);
    });
  }

  const rows = useMemo(() => {
    const result: { row: number; start: number; end: number }[] = [];
    for (let i = 0; i < numRows; i++) {
      const start = i * leavesPerRow;
      const end = Math.min((i + 1) * leavesPerRow, treeSize);
      result.push({ row: i, start, end });
    }
    return result;
  }, [numRows, leavesPerRow, treeSize]);

  const proofLeafRow = useMemo(() => {
    if (!proof || proof.tree_size <= 0) return null;
    const rowIdx = Math.floor(proof.leaf_index / leavesPerRow);
    if (rowIdx >= numRows) return null;
    return {
      row: rowIdx,
      x: toRowX(proof.leaf_index, rowIdx * leavesPerRow),
      y: rowY(rowIdx),
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [proof, leavesPerRow, numRows, effectiveBarWidth]);

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

          {/* Line from root badge to first row */}
          <line
            x1={svgCx}
            y1={ROOT_Y + ROOT_H}
            x2={svgCx}
            y2={FIRST_ROW_Y}
            stroke="var(--pf-t--global--color--brand--default, #0066cc)"
            strokeWidth={1.5}
          />

          {treeSize === 0 ? (
            <text x={svgCx} y={FIRST_ROW_Y + 40} textAnchor="middle" fontSize={12}
              fill="var(--pf-t--global--color--nonstatus--gray--default, #666)">
              No leaves yet
            </text>
          ) : (
            <>
              {/* Zoom controls (rendered as SVG foreignObject) */}
              {treeSize > 1000 && (
                <foreignObject x={barWidth - 200} y={ROOT_Y + ROOT_H + 4} width={200} height={24}>
                  <div style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'flex-end',
                    gap: '0.25rem', fontSize: '0.75rem',
                    color: 'var(--pf-t--global--text--color--subtle, #6a6e73)',
                  }}>
                    <button onClick={handleZoomIn} style={{
                      background: 'none', border: '1px solid var(--pf-t--global--border--color--default, #8a8d90)',
                      borderRadius: 3, cursor: 'pointer', padding: '0 4px', lineHeight: '18px',
                      color: 'inherit',
                    }}>−</button>
                    <span>{leavesPerRow.toLocaleString()}/row</span>
                    <button onClick={handleZoomOut} style={{
                      background: 'none', border: '1px solid var(--pf-t--global--border--color--default, #8a8d90)',
                      borderRadius: 3, cursor: 'pointer', padding: '0 4px', lineHeight: '18px',
                      color: 'inherit',
                    }}>+</button>
                  </div>
                </foreignObject>
              )}

              {rows.map(({ row, start, end }) => {
                const by = rowY(row);
                const tickTop = by - TICK_ABOVE;
                const tickBot = by + BAR_H + TICK_BELOW;
                const rowWidth = toRowX(end, start) - RANGE_LABEL_W;
                const isLastRow = row === numRows - 1;

                const landmarkedEnd = Math.min(Math.max(lastLandmarkSize, start), end);
                const hasLandmarked = lastLandmarkSize > start;

                const fullyLandmarked = lastLandmarkSize >= end;

                const rowLandmarks = landmarks.filter(
                  (lm) => lm.tree_size > start && lm.tree_size <= end
                );
                const rowLabelStep = rowLandmarks.length > LABEL_STEP_THRESHOLD
                  ? Math.ceil(rowLandmarks.length / LABEL_STEP_THRESHOLD)
                  : 1;

                const cpInRow = cpSize !== null && cpSize > start && cpSize <= end;

                return (
                  <g key={`row-${row}`}>
                    {/* Row range label */}
                    <text
                      x={RANGE_LABEL_W - 6}
                      y={by + BAR_H / 2 + 4}
                      textAnchor="end"
                      fontSize={9}
                      fill="var(--pf-t--global--text--color--subtle, #6a6e73)"
                      fontFamily="var(--pf-t--global--font--family--mono, monospace)"
                    >
                      {start.toLocaleString()}
                    </text>

                    {/* Landmarked portion (green) */}
                    {hasLandmarked && (
                      <rect
                        x={RANGE_LABEL_W}
                        y={by}
                        width={toRowX(landmarkedEnd, start) - RANGE_LABEL_W}
                        height={BAR_H}
                        fill="var(--pf-t--global--color--status--success--default, #3e8635)"
                      />
                    )}

                    {/* Active (un-landmarked) portion (orange) */}
                    {!fullyLandmarked && (
                      <rect
                        x={toRowX(Math.max(landmarkedEnd, start), start)}
                        y={by}
                        width={RANGE_LABEL_W + rowWidth - toRowX(Math.max(landmarkedEnd, start), start)}
                        height={BAR_H}
                        fill="var(--pf-t--global--color--status--warning--default, #f0ab00)"
                      />
                    )}

                    {/* Revoked range overlays */}
                    {revokedRanges.map((r) => {
                      const rStart = Math.max(r.start, start);
                      const rEnd = Math.min(r.end, end);
                      if (rStart > rEnd) return null;
                      const naturalX = toRowX(rStart, start);
                      const naturalW = toRowX(rEnd + 1, start) - naturalX;
                      const MIN_W = 8;
                      const displayW = Math.max(MIN_W, naturalW);
                      const displayX = naturalX - (displayW - naturalW) / 2;
                      return (
                        <rect
                          key={`rev-${row}-${r.start}-${r.end}`}
                          x={Math.max(RANGE_LABEL_W, displayX)}
                          y={by}
                          width={displayW}
                          height={BAR_H}
                          fill="var(--pf-t--global--color--status--danger--default, #c9190b)"
                        />
                      );
                    })}

                    {/* Landmark tick marks */}
                    {rowLandmarks.map((lm, i) => {
                      const lx = toRowX(lm.tree_size, start);
                      const showLabel = i % rowLabelStep === 0;
                      return (
                        <g key={`lm-${lm.sequence_no}`}>
                          <line
                            x1={lx}
                            y1={tickTop}
                            x2={lx}
                            y2={tickBot}
                            stroke="var(--pf-t--global--border--color--default, #8a8d90)"
                            strokeWidth={1}
                          />
                          {showLabel && (
                            <>
                              <text
                                x={lx}
                                y={tickTop - 2}
                                textAnchor="middle"
                                fontSize={9}
                                fill="var(--pf-t--global--text--color--subtle, #6a6e73)"
                              >
                                LM#{lm.sequence_no}
                              </text>
                              <text
                                x={lx}
                                y={tickBot + 12}
                                textAnchor="middle"
                                fontSize={9}
                                fill="var(--pf-t--global--text--color--subtle, #6a6e73)"
                              >
                                {lm.tree_size.toLocaleString()}
                              </text>
                            </>
                          )}
                        </g>
                      );
                    })}

                    {/* Checkpoint marker */}
                    {cpInRow && (
                      <g>
                        <line
                          x1={toRowX(cpSize!, start)}
                          y1={by - 26}
                          x2={toRowX(cpSize!, start)}
                          y2={by + BAR_H}
                          stroke="var(--pf-t--global--color--brand--default, #0066cc)"
                          strokeWidth={2}
                        />
                        <text
                          x={toRowX(cpSize!, start)}
                          y={by - 28}
                          textAnchor="middle"
                          fontSize={9}
                          fontWeight="bold"
                          fill="var(--pf-t--global--color--brand--default, #0066cc)"
                        >
                          CP
                        </text>
                      </g>
                    )}

                    {/* Row end label */}
                    {isLastRow && (
                      <text
                        x={RANGE_LABEL_W + rowWidth}
                        y={by + BAR_H + 12}
                        textAnchor="end"
                        fontSize={9}
                        fill="var(--pf-t--global--text--color--subtle, #6a6e73)"
                      >
                        {treeSize.toLocaleString()}
                      </text>
                    )}

                    {/* Continuation arrow for non-last rows */}
                    {!isLastRow && (
                      <text
                        x={RANGE_LABEL_W + rowWidth + 4}
                        y={by + BAR_H / 2 + 4}
                        fontSize={10}
                        fill="var(--pf-t--global--text--color--subtle, #6a6e73)"
                      >
                        ↵
                      </text>
                    )}
                  </g>
                );
              })}

              {/* Proof leaf marker */}
              {proofLeafRow && (
                <>
                  <line
                    x1={proofLeafRow.x}
                    y1={proofLeafRow.y - 6}
                    x2={proofLeafRow.x}
                    y2={proofLeafRow.y + BAR_H + 6}
                    stroke="var(--pf-t--global--color--status--info--default, #009596)"
                    strokeWidth={1.5}
                    strokeDasharray="4 3"
                  />
                  <circle
                    cx={proofLeafRow.x}
                    cy={proofLeafRow.y + BAR_H / 2}
                    r={5}
                    fill="var(--pf-t--global--color--status--info--default, #009596)"
                  />
                  <text
                    x={proofLeafRow.x}
                    y={proofLeafRow.y + BAR_H + 20}
                    textAnchor="middle"
                    fontSize={9}
                    fill="var(--pf-t--global--color--status--info--default, #009596)"
                  >
                    leaf #{proof?.leaf_index.toLocaleString()}
                  </text>
                </>
              )}

              {/* Proof node chain */}
              {proof && (
                <>
                  <text
                    x={4}
                    y={lastRowBottom + 10}
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
                      y={lastRowBottom + 28 + idx * 22}
                      fontSize={10}
                      fontFamily="var(--pf-t--global--font--family--mono, monospace)"
                      fill="var(--pf-t--global--text--color--regular, #151515)"
                    >
                      [{idx}] {abbrev(node.hash)}
                    </text>
                  ))}
                  <text
                    x={4}
                    y={lastRowBottom + 28 + proof.proof.length * 22}
                    fontSize={10}
                    fontFamily="var(--pf-t--global--font--family--mono, monospace)"
                    fill="var(--pf-t--global--color--brand--default, #0066cc)"
                  >
                    root: {abbrev(proof.tree_size === treeSize ? rootHash : '(different tree size)')}
                  </text>
                </>
              )}

              {/* Fully landmarked label */}
              {lastLandmarkSize >= treeSize && landmarks.length > 0 && (
                <text
                  x={barWidth - 4}
                  y={rowY(numRows - 1) + BAR_H + 24}
                  textAnchor="end"
                  fontSize={9}
                  fill="var(--pf-t--global--color--status--success--default, #3e8635)"
                >
                  All leaves landmarked (LM#{landmarks[landmarks.length - 1].sequence_no})
                </text>
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
            Leaf index <strong>{proof.leaf_index.toLocaleString()}</strong> of <strong>{proof.tree_size.toLocaleString()}</strong> leaves
            &nbsp;·&nbsp; {proof.proof.length} sibling hash{proof.proof.length !== 1 ? 'es' : ''}
          </div>
        )}
      </div>
    </div>
  );
}
