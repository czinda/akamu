import { useEffect, useState, useCallback } from 'react';
import {
  PageSection,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  Button,
  Spinner,
  Alert,
  EmptyState,
  EmptyStateBody,
  Modal,
  ModalHeader,
  ModalBody,
  ModalFooter,
  Label,
  Form,
  FormGroup,
  TextArea,
  TextInput,
  Radio,
  ClipboardCopy,
} from '@patternfly/react-core';
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
} from '@patternfly/react-table';
import { useNavigate } from 'react-router-dom';
import { listCas, forceCrl, crossSign, CrossSignResult, CaInfo } from '../../api/cas';
import { useAuth, hasRole } from '../../auth/AuthContext';
import { fmtTs } from '../../utils';
import { errorMessage } from '../../api/client';

export default function CAs() {
  const { role } = useAuth();
  const canWrite = hasRole(role, 'ca_operations');
  const navigate = useNavigate();

  const [cas, setCas] = useState<CaInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Force-CRL state
  const [crlCaId, setCrlCaId] = useState<string | null>(null);

  // Cross-sign state
  const [crossSignIssuerId, setCrossSignIssuerId] = useState<string | null>(null);
  const [crossSignMode, setCrossSignMode] = useState<'local' | 'external'>('local');
  const [crossSignSubjectId, setCrossSignSubjectId] = useState('');
  const [crossSignPem, setCrossSignPem] = useState('');
  const [crossSignYears, setCrossSignYears] = useState(5);
  const [crossSignResult, setCrossSignResult] = useState<CrossSignResult | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listCas();
      setCas(result.cas);
    } catch (e: unknown) {
      setError(errorMessage(e, 'Failed to load CAs'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  function openCrossSign(caId: string) {
    setCrossSignIssuerId(caId);
    setCrossSignMode('local');
    setCrossSignSubjectId('');
    setCrossSignPem('');
    setCrossSignYears(5);
    setCrossSignResult(null);
  }

  function closeCrossSign() {
    setCrossSignIssuerId(null);
    setCrossSignResult(null);
  }

  async function handleForceCrl() {
    if (crlCaId === null) return;
    setSaving(true);
    try {
      await forceCrl(crlCaId || undefined);
      setCrlCaId(null);
    } catch (e: unknown) {
      setError(errorMessage(e, 'Force CRL failed'));
    } finally {
      setSaving(false);
    }
  }

  async function handleCrossSign(e: React.FormEvent) {
    e.preventDefault();
    if (!crossSignIssuerId) return;
    setSaving(true);
    setError(null);
    try {
      const opts = crossSignMode === 'local'
        ? { subject_ca_id: crossSignSubjectId, validity_years: crossSignYears }
        : { subject_cert_pem: crossSignPem, validity_years: crossSignYears };
      const result = await crossSign(crossSignIssuerId, opts);
      setCrossSignResult(result);
    } catch (err: unknown) {
      setError(errorMessage(err, 'Cross-sign failed'));
    } finally {
      setSaving(false);
    }
  }

  const localSubjectCas = cas.filter(c => c.id !== crossSignIssuerId);
  const crossSignValid = crossSignMode === 'local'
    ? !!crossSignSubjectId
    : crossSignPem.trim().length > 0;

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Certification Authorities</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        {canWrite && (
          <Toolbar>
            <ToolbarContent>
              <ToolbarItem>
                <Button variant="secondary" onClick={() => setCrlCaId('')}>Force Global CRL</Button>
              </ToolbarItem>
            </ToolbarContent>
          </Toolbar>
        )}
        {loading && <Spinner />}
        {!loading && cas.length === 0 && (
          <EmptyState><EmptyStateBody>No CAs found.</EmptyStateBody></EmptyState>
        )}
        {!loading && cas.length > 0 && (
          <Table aria-label="CAs">
            <Thead>
              <Tr>
                <Th>ID</Th>
                <Th>Key Type</Th>
                <Th>Hash Alg</Th>
                <Th>Validity Days</Th>
                <Th>Default</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {cas.map(ca => (
                <Tr key={ca.id}>
                  <Td>{ca.id}</Td>
                  <Td>{ca.key_type}</Td>
                  <Td>{ca.hash_alg}</Td>
                  <Td>{ca.validity_days}</Td>
                  <Td>{ca.is_default ? <Label color="green">default</Label> : null}</Td>
                  <Td>
                    {canWrite && (
                      <>
                        <Button variant="secondary" size="sm" onClick={() => setCrlCaId(ca.id)}>Force CRL</Button>{' '}
                        <Button variant="secondary" size="sm" onClick={() => openCrossSign(ca.id)}>Cross-Sign</Button>{' '}
                      </>
                    )}
                    <Button variant="plain" size="sm" onClick={() => navigate(`/cas/${ca.id}`)}>View</Button>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </PageSection>

      {/* Force CRL modal */}
      <Modal variant="small" isOpen={crlCaId !== null} onClose={() => setCrlCaId(null)}>
        <ModalHeader title="Force CRL" />
        <ModalBody>
          <p>{crlCaId ? `Force CRL for CA ${crlCaId}?` : 'Force global CRL for all CAs?'}</p>
        </ModalBody>
        <ModalFooter>
          <Button variant="primary" onClick={handleForceCrl} isLoading={saving} isDisabled={saving}>Force CRL</Button>
          <Button variant="link" onClick={() => setCrlCaId(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>

      {/* Cross-sign modal */}
      <Modal variant="medium" isOpen={!!crossSignIssuerId} onClose={closeCrossSign}>
        <ModalHeader title={`Issue Cross-Certificate — Issuer: ${crossSignIssuerId}`} />
        <ModalBody>
          {crossSignResult ? (
            /* ── Success view ─────────────────────────────── */
            <div>
              <Alert variant="success" isInline title="Cross-certificate issued" style={{ marginBottom: '1rem' }}>
                Subject: <strong>{crossSignResult.subject_dn}</strong><br />
                Serial: <code>{crossSignResult.serial_number}</code><br />
                Valid until: {fmtTs(crossSignResult.not_after)}
              </Alert>
              <FormGroup label="Certificate PEM" fieldId="xsign-result-pem">
                <ClipboardCopy isReadOnly isCode hoverTip="Copy" clickTip="Copied" variant="expansion">
                  {crossSignResult.cross_cert_pem}
                </ClipboardCopy>
              </FormGroup>
            </div>
          ) : (
            /* ── Input form ───────────────────────────────── */
            <Form id="cross-sign-form" onSubmit={handleCrossSign}>
              <FormGroup label="Subject" isRequired fieldId="xsign-mode">
                <div style={{ display: 'flex', gap: '2rem', marginBottom: '0.75rem' }}>
                  <Radio id="xsign-local" name="xsign-mode" label="CA on this server"
                    isChecked={crossSignMode === 'local'}
                    onChange={() => { setCrossSignMode('local'); setCrossSignSubjectId(''); }} />
                  <Radio id="xsign-external" name="xsign-mode" label="External CA (paste PEM)"
                    isChecked={crossSignMode === 'external'}
                    onChange={() => { setCrossSignMode('external'); setCrossSignPem(''); }} />
                </div>
                {crossSignMode === 'local' ? (
                  localSubjectCas.length > 0 ? (
                    <select
                      id="xsign-subject-id"
                      value={crossSignSubjectId}
                      onChange={e => setCrossSignSubjectId(e.target.value)}
                      style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px',
                        fontSize: 'inherit', width: '100%' }}
                    >
                      <option value="">— select subject CA —</option>
                      {localSubjectCas.map(c => (
                        <option key={c.id} value={c.id}>{c.id} ({c.key_type})</option>
                      ))}
                    </select>
                  ) : (
                    <Alert variant="warning" isInline title="No other CAs available on this server" />
                  )
                ) : (
                  <TextArea
                    id="xsign-pem"
                    value={crossSignPem}
                    onChange={(_e, v) => setCrossSignPem(v)}
                    rows={10}
                    placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                    style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                    isRequired
                  />
                )}
              </FormGroup>
              <FormGroup label="Validity (years)" isRequired fieldId="xsign-years">
                <TextInput
                  id="xsign-years"
                  type="number"
                  value={String(crossSignYears)}
                  onChange={(_e, v) => setCrossSignYears(Math.max(1, Math.min(50, parseInt(v, 10) || 5)))}
                  style={{ maxWidth: '8rem' }}
                />
                <p style={{ marginTop: '0.25rem', fontSize: '0.8rem', color: '#6a6e73' }}>1–50 years. Default is 5.</p>
              </FormGroup>
            </Form>
          )}
        </ModalBody>
        <ModalFooter>
          {crossSignResult ? (
            <>
              <Button variant="primary" component="a"
                onClick={() => navigate(`/cross-certs`)}>
                View in Cross-Certs
              </Button>
              <Button variant="link" onClick={closeCrossSign}>Close</Button>
            </>
          ) : (
            <>
              <Button form="cross-sign-form" type="submit" variant="primary"
                isLoading={saving} isDisabled={saving || !crossSignValid}>
                Issue Cross-Certificate
              </Button>
              <Button variant="link" onClick={closeCrossSign} isDisabled={saving}>Cancel</Button>
            </>
          )}
        </ModalFooter>
      </Modal>
    </>
  );
}
