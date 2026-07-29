import { useEffect, useState, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  Button,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
  ExpandableSection,
  TextInput,
  ActionGroup,
} from '@patternfly/react-core';
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
} from '@patternfly/react-table';
import {
  getRoot,
  getLandmarks,
  getCheckpoint,
  getCosignature,
  getLogListEntry,
  getRevokedRanges,
  getConsistencyProof,
  getSubtreeRoot,
  forceCheckpoint,
  forceLandmark,
  downloadLandmarkCert,
  type MtcRoot,
  type MtcLandmark,
  type MtcRevokedRange,
  type MtcConsistencyProof,
  type MtcSubtreeRoot,
} from '../../api/mtc';
import MtcTree from '../../components/MtcTree';
import { fmtTs, triggerBlobDownload } from '../../utils';
import { useAuth, hasRole } from '../../auth/AuthContext';
import { errorMessage } from '../../api/client';

export default function MtcDetail() {
  const { caId } = useParams<{ caId: string }>();
  const { role } = useAuth();
  const canOperate = hasRole(role, 'ca_operations');

  const [loading, setLoading] = useState(true);

  const [root, setRoot] = useState<MtcRoot | null>(null);
  const [rootError, setRootError] = useState<string | null>(null);

  const [landmarks, setLandmarks] = useState<MtcLandmark[]>([]);
  const [landmarksError, setLandmarksError] = useState<string | null>(null);

  const [checkpoint, setCheckpoint] = useState<string | null>(null);
  const [checkpointError, setCheckpointError] = useState<string | null>(null);

  const [cosignature, setCosignature] = useState<string | null>(null);
  const [cosignatureError, setCosignatureError] = useState<string | null>(null);

  const [logListEntry, setLogListEntry] = useState<string | null>(null);
  const [logListEntryError, setLogListEntryError] = useState<string | null>(null);

  const [revokedRanges, setRevokedRanges] = useState<MtcRevokedRange[]>([]);
  const [revokedError, setRevokedError] = useState<string | null>(null);

  const [confirmAction, setConfirmAction] = useState<'checkpoint' | 'landmark' | null>(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Advanced verification
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [cpFrom, setCpFrom] = useState('');
  const [cpTo, setCpTo] = useState('');
  const [cpResult, setCpResult] = useState<MtcConsistencyProof | null>(null);
  const [cpError, setCpError] = useState<string | null>(null);
  const [cpLoading, setCpLoading] = useState(false);

  const [srStart, setSrStart] = useState('');
  const [srEnd, setSrEnd] = useState('');
  const [srResult, setSrResult] = useState<MtcSubtreeRoot | null>(null);
  const [srError, setSrError] = useState<string | null>(null);
  const [srLoading, setSrLoading] = useState(false);

  const loadData = useCallback(async (signal?: AbortSignal) => {
    if (!caId) return;
    setLoading(true);
    setRootError(null);
    setLandmarksError(null);
    setCheckpointError(null);
    setCosignatureError(null);
    setLogListEntryError(null);
    setRevokedError(null);
    const [rootRes, landmarksRes, checkpointRes, cosignatureRes, logListRes, revokedRes] = await Promise.allSettled([
      getRoot(caId),
      getLandmarks(caId),
      getCheckpoint(caId),
      getCosignature(caId),
      getLogListEntry(caId),
      getRevokedRanges(caId),
    ]);
    if (signal?.aborted) return;

    if (rootRes.status === 'fulfilled') setRoot(rootRes.value);
    else setRootError(errorMessage(rootRes.reason, 'Failed to load tree root'));

    if (landmarksRes.status === 'fulfilled') setLandmarks(landmarksRes.value);
    else setLandmarksError(errorMessage(landmarksRes.reason, 'Failed to load landmarks'));

    if (checkpointRes.status === 'fulfilled') setCheckpoint(checkpointRes.value);
    else setCheckpointError(errorMessage(checkpointRes.reason, 'Unavailable'));

    if (cosignatureRes.status === 'fulfilled') setCosignature(cosignatureRes.value);
    else setCosignatureError(errorMessage(cosignatureRes.reason, 'Unavailable'));

    if (logListRes.status === 'fulfilled') setLogListEntry(logListRes.value);
    else setLogListEntryError(errorMessage(logListRes.reason, 'Unavailable'));

    if (revokedRes.status === 'fulfilled') setRevokedRanges(revokedRes.value);
    else setRevokedError(errorMessage(revokedRes.reason, 'Failed to load revoked ranges'));

    setLoading(false);
  }, [caId]);

  useEffect(() => {
    const controller = new AbortController();
    loadData(controller.signal);
    return () => controller.abort();
  }, [loadData]);

  async function handleForce() {
    if (!caId || !confirmAction) return;
    setActionBusy(true);
    setActionError(null);
    try {
      if (confirmAction === 'checkpoint') await forceCheckpoint(caId);
      else await forceLandmark(caId);
      setConfirmAction(null);
      await loadData();
    } catch (e: unknown) {
      setActionError(errorMessage(e, 'Action failed'));
    } finally {
      setActionBusy(false);
    }
  }

  async function handleDownloadLandmarkCert(seq: number) {
    if (!caId) return;
    try {
      const blob = await downloadLandmarkCert(seq, caId);
      triggerBlobDownload(blob, `landmark-${seq}.der`);
    } catch (e: unknown) {
      setLandmarksError(errorMessage(e, 'Download failed'));
    }
  }

  async function handleConsistencyProof() {
    if (!caId) return;
    const from = Number(cpFrom);
    const to = Number(cpTo);
    if (!Number.isInteger(from) || !Number.isInteger(to) || from < 0 || to < 0) { setCpError('Enter valid non-negative integers'); return; }
    setCpLoading(true);
    setCpError(null);
    setCpResult(null);
    try {
      const result = await getConsistencyProof(caId, from, to);
      setCpResult(result);
    } catch (e: unknown) {
      setCpError(errorMessage(e, 'Failed'));
    } finally {
      setCpLoading(false);
    }
  }

  async function handleSubtreeRoot() {
    if (!caId) return;
    const start = Number(srStart);
    const end = Number(srEnd);
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < 0) { setSrError('Enter valid non-negative integers'); return; }
    setSrLoading(true);
    setSrError(null);
    setSrResult(null);
    try {
      const result = await getSubtreeRoot(caId, start, end);
      setSrResult(result);
    } catch (e: unknown) {
      setSrError(errorMessage(e, 'Failed'));
    } finally {
      setSrLoading(false);
    }
  }

  const preStyle: React.CSSProperties = {
    fontFamily: 'var(--pf-t--global--font--family--mono)',
    fontSize: '0.85rem',
    background: 'var(--pf-t--global--background--color--secondary--default)',
    border: '1px solid var(--pf-t--global--border--color--default)',
    borderRadius: 'var(--pf-t--global--border--radius--small)',
    padding: '1rem',
    overflowX: 'auto',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
  };

  return (
    <>
      <PageSection>
        <Link to="/mtc" style={{ fontSize: '0.875rem' }}>← Back to Transparency Log</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>MTC: {caId}</Title>
      </PageSection>
      <PageSection>
        {loading && <Spinner />}
        {!loading && (
          <>
            {/* Tree State */}
            <Title headingLevel="h2" size="lg" style={{ marginBottom: '0.5rem' }}>Tree State</Title>
            {rootError && <Alert variant="warning" title={rootError} isInline style={{ marginBottom: '1rem' }} />}
            {root && (
              <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: '640px', marginBottom: '1.5rem' }}>
                <DescriptionListGroup>
                  <DescriptionListTerm>Tree Size</DescriptionListTerm>
                  <DescriptionListDescription>{root.tree_size}</DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>Root Hash</DescriptionListTerm>
                  <DescriptionListDescription>
                    <code style={{ fontSize: '0.875rem' }}>{root.root_hash}</code>
                  </DescriptionListDescription>
                </DescriptionListGroup>
              </DescriptionList>
            )}

            {/* Tree Visualization */}
            {root && (
              <>
                <Title headingLevel="h2" size="lg" style={{ marginBottom: '0.5rem' }}>Tree Visualization</Title>
                <div style={{ marginBottom: '1.5rem' }}>
                  <MtcTree
                    root={root}
                    landmarks={landmarks}
                    revokedRanges={revokedRanges}
                    checkpoint={checkpoint}
                  />
                </div>
              </>
            )}

            {/* Actions */}
            {canOperate && (
              <div style={{ marginBottom: '1.5rem' }}>
                {actionError && <Alert variant="danger" title={actionError} isInline style={{ marginBottom: '0.5rem' }} />}
                <Button variant="secondary" size="sm" onClick={() => setConfirmAction('checkpoint')}
                  style={{ marginRight: '0.5rem' }}>
                  Force Checkpoint
                </Button>
                <Button variant="secondary" size="sm" onClick={() => setConfirmAction('landmark')}>
                  Force Landmark
                </Button>
              </div>
            )}

            {/* Landmarks */}
            <Title headingLevel="h2" size="lg" style={{ marginBottom: '0.5rem' }}>Landmarks</Title>
            {landmarksError && <Alert variant="warning" title={landmarksError} isInline style={{ marginBottom: '1rem' }} />}
            {landmarks.length === 0 && !landmarksError && <p>No landmarks yet.</p>}
            {landmarks.length > 0 && (
              <Table aria-label="Landmarks" style={{ marginBottom: '1.5rem' }}>
                <Thead>
                  <Tr>
                    <Th>Sequence No</Th>
                    <Th>Tree Size</Th>
                    <Th>Created At</Th>
                    <Th>Actions</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {landmarks.map((lm) => (
                    <Tr key={lm.sequence_no}>
                      <Td>{lm.sequence_no}</Td>
                      <Td>{lm.tree_size}</Td>
                      <Td>{fmtTs(lm.created_at)}</Td>
                      <Td>
                        <Link to={`/mtc/${caId}/landmarks/${lm.sequence_no}`} style={{ fontSize: '0.875rem' }}>
                          View
                        </Link>
                        {canOperate && (
                          <Button variant="plain" size="sm"
                            onClick={() => handleDownloadLandmarkCert(lm.sequence_no)}>
                            Download Cert
                          </Button>
                        )}
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            )}

            {/* Checkpoint */}
            <Title headingLevel="h2" size="lg" style={{ marginBottom: '0.5rem' }}>Checkpoint</Title>
            {checkpointError && <Alert variant="warning" title={checkpointError} isInline style={{ marginBottom: '1rem' }} />}
            {checkpoint && <pre style={{ ...preStyle, marginBottom: '1.5rem' }}>{checkpoint}</pre>}

            {/* Cosignature */}
            <Title headingLevel="h2" size="lg" style={{ marginBottom: '0.5rem' }}>Cosignature</Title>
            {cosignatureError && <Alert variant="warning" title={cosignatureError} isInline style={{ marginBottom: '1rem' }} />}
            {cosignature && <pre style={{ ...preStyle, marginBottom: '1.5rem' }}>{cosignature}</pre>}

            {/* Log-List Entry */}
            {(logListEntry || logListEntryError) && (
              <>
                <Title headingLevel="h2" size="lg" style={{ marginBottom: '0.5rem' }}>Log-List Entry</Title>
                {logListEntryError && <Alert variant="warning" title={logListEntryError} isInline style={{ marginBottom: '1rem' }} />}
                {logListEntry && <pre style={{ ...preStyle, marginBottom: '1.5rem' }}>{logListEntry}</pre>}
              </>
            )}

            {/* Revoked Ranges */}
            <Title headingLevel="h2" size="lg" style={{ marginBottom: '0.5rem' }}>Revoked Ranges</Title>
            {revokedError && <Alert variant="warning" title={revokedError} isInline style={{ marginBottom: '1rem' }} />}
            {revokedRanges.length === 0 && !revokedError && <p style={{ marginBottom: '1.5rem' }}>No revoked ranges.</p>}
            {revokedRanges.length > 0 && (
              <Table aria-label="Revoked Ranges" style={{ marginBottom: '1.5rem' }}>
                <Thead>
                  <Tr>
                    <Th>Start</Th>
                    <Th>End</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {revokedRanges.map((r) => (
                    <Tr key={`${r.start}-${r.end}`}>
                      <Td>{r.start}</Td>
                      <Td>{r.end}</Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            )}

            {/* Advanced Verification */}
            <ExpandableSection
              toggleText={advancedOpen ? 'Hide Advanced Verification' : 'Show Advanced Verification'}
              isExpanded={advancedOpen}
              onToggle={(_e, expanded) => setAdvancedOpen(expanded)}
            >
              <div style={{ marginTop: '1rem' }}>
                <Title headingLevel="h3" size="md" style={{ marginBottom: '0.5rem' }}>Consistency Proof</Title>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-end', marginBottom: '0.5rem' }}>
                  <div>
                    <label htmlFor="cp-from" style={{ display: 'block', fontSize: '0.85rem' }}>From</label>
                    <TextInput id="cp-from" type="number" value={cpFrom} onChange={(_e, v) => setCpFrom(v)} style={{ width: '120px' }} />
                  </div>
                  <div>
                    <label htmlFor="cp-to" style={{ display: 'block', fontSize: '0.85rem' }}>To</label>
                    <TextInput id="cp-to" type="number" value={cpTo} onChange={(_e, v) => setCpTo(v)} style={{ width: '120px' }} />
                  </div>
                  <Button variant="secondary" size="sm" onClick={handleConsistencyProof} isLoading={cpLoading} isDisabled={cpLoading}>
                    Verify
                  </Button>
                </div>
                {cpError && <Alert variant="danger" title={cpError} isInline style={{ marginBottom: '0.5rem' }} />}
                {cpResult && (
                  <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: '640px', marginBottom: '1rem' }}>
                    <DescriptionListGroup>
                      <DescriptionListTerm>From Size</DescriptionListTerm>
                      <DescriptionListDescription>{cpResult.from_size}</DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>From Root</DescriptionListTerm>
                      <DescriptionListDescription><code style={{ fontSize: '0.85rem' }}>{cpResult.from_root}</code></DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>To Size</DescriptionListTerm>
                      <DescriptionListDescription>{cpResult.to_size}</DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>To Root</DescriptionListTerm>
                      <DescriptionListDescription><code style={{ fontSize: '0.85rem' }}>{cpResult.to_root}</code></DescriptionListDescription>
                    </DescriptionListGroup>
                  </DescriptionList>
                )}

                <Title headingLevel="h3" size="md" style={{ marginBottom: '0.5rem', marginTop: '1rem' }}>Subtree Root</Title>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-end', marginBottom: '0.5rem' }}>
                  <div>
                    <label htmlFor="sr-start" style={{ display: 'block', fontSize: '0.85rem' }}>Start</label>
                    <TextInput id="sr-start" type="number" value={srStart} onChange={(_e, v) => setSrStart(v)} style={{ width: '120px' }} />
                  </div>
                  <div>
                    <label htmlFor="sr-end" style={{ display: 'block', fontSize: '0.85rem' }}>End</label>
                    <TextInput id="sr-end" type="number" value={srEnd} onChange={(_e, v) => setSrEnd(v)} style={{ width: '120px' }} />
                  </div>
                  <Button variant="secondary" size="sm" onClick={handleSubtreeRoot} isLoading={srLoading} isDisabled={srLoading}>
                    Compute
                  </Button>
                </div>
                {srError && <Alert variant="danger" title={srError} isInline style={{ marginBottom: '0.5rem' }} />}
                {srResult && (
                  <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: '640px' }}>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Start</DescriptionListTerm>
                      <DescriptionListDescription>{srResult.start}</DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>End</DescriptionListTerm>
                      <DescriptionListDescription>{srResult.end}</DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Root Hash</DescriptionListTerm>
                      <DescriptionListDescription><code style={{ fontSize: '0.85rem' }}>{srResult.root_hash}</code></DescriptionListDescription>
                    </DescriptionListGroup>
                  </DescriptionList>
                )}
              </div>
            </ExpandableSection>
          </>
        )}
      </PageSection>

      {/* Force confirmation modal */}
      {confirmAction && (
        <Modal
          isOpen
          variant="small"
          onClose={() => { setConfirmAction(null); setActionError(null); }}
        >
          <ModalHeader title={confirmAction === 'checkpoint' ? 'Force Checkpoint' : 'Force Landmark'} />
          <ModalBody>
            This will force an immediate MTC {confirmAction} for CA <strong>{caId}</strong>.
            An audit event will be recorded. Continue?
            {actionError && <Alert variant="danger" title={actionError} isInline style={{ marginTop: '0.5rem' }} />}
          </ModalBody>
          <ModalFooter>
            <ActionGroup>
              <Button variant="primary" onClick={handleForce} isLoading={actionBusy} isDisabled={actionBusy}>
                Confirm
              </Button>
              <Button variant="link" onClick={() => { setConfirmAction(null); setActionError(null); }}>
                Cancel
              </Button>
            </ActionGroup>
          </ModalFooter>
        </Modal>
      )}
    </>
  );
}
