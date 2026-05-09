import React, { useEffect, useState, useCallback } from 'react';
import {
  PageSection,
  PageSectionVariants,
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
  ModalVariant,
  Label,
  Form,
  FormGroup,
  TextArea,
} from '@patternfly/react-core';
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
} from '@patternfly/react-table';
import { listCas, forceCrl, crossSign, CaInfo } from '../../api/cas';
import { useAuth, hasRole } from '../../auth/AuthContext';

export default function CAs() {
  const { role } = useAuth();
  const canWrite = hasRole(role, 'ca_operations');

  const [cas, setCas] = useState<CaInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [crlCaId, setCrlCaId] = useState<string | null>(null);
  const [crossSignCaId, setCrossSignCaId] = useState<string | null>(null);
  const [crossSignPem, setCrossSignPem] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listCas();
      setCas(result.cas);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load CAs');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleForceCrl() {
    if (crlCaId === null) return;
    setSaving(true);
    try {
      await forceCrl(crlCaId || undefined);
      setCrlCaId(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Force CRL failed');
    } finally {
      setSaving(false);
    }
  }

  async function handleCrossSign(e: React.FormEvent) {
    e.preventDefault();
    if (!crossSignCaId) return;
    setSaving(true);
    try {
      await crossSign(crossSignCaId, { cert_pem: crossSignPem });
      setCrossSignCaId(null);
      setCrossSignPem('');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Cross-sign failed');
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
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
                {canWrite && <Th>Actions</Th>}
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
                  {canWrite && (
                    <Td>
                      <Button variant="secondary" size="sm" onClick={() => setCrlCaId(ca.id)}>Force CRL</Button>{' '}
                      <Button variant="secondary" size="sm" onClick={() => setCrossSignCaId(ca.id)}>Cross-Sign</Button>
                    </Td>
                  )}
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </PageSection>
      <Modal
        variant={ModalVariant.small}
        title="Force CRL"
        isOpen={crlCaId !== null}
        onClose={() => setCrlCaId(null)}
        actions={[
          <Button key="confirm" variant="primary" onClick={handleForceCrl} isLoading={saving} isDisabled={saving}>Force CRL</Button>,
          <Button key="cancel" variant="link" onClick={() => setCrlCaId(null)}>Cancel</Button>,
        ]}
      >
        <p>{crlCaId ? `Force CRL for CA ${crlCaId}?` : 'Force global CRL for all CAs?'}</p>
      </Modal>
      <Modal
        variant={ModalVariant.medium}
        title={`Cross-Sign with CA ${crossSignCaId}`}
        isOpen={!!crossSignCaId}
        onClose={() => setCrossSignCaId(null)}
        actions={[
          <Button key="save" form="cross-sign-form" type="submit" variant="primary" isLoading={saving} isDisabled={saving}>Cross-Sign</Button>,
          <Button key="cancel" variant="link" onClick={() => setCrossSignCaId(null)}>Cancel</Button>,
        ]}
      >
        <Form id="cross-sign-form" onSubmit={handleCrossSign}>
          <FormGroup label="Certificate PEM" isRequired fieldId="cross-sign-pem">
            <TextArea id="cross-sign-pem" value={crossSignPem} onChange={(_e, v) => setCrossSignPem(v)} rows={12} isRequired />
          </FormGroup>
        </Form>
      </Modal>
    </>
  );
}
