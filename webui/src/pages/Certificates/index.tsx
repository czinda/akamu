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
  ModalHeader,
  ModalBody,
  ModalFooter,
  Pagination,
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
import { listCerts, revokeCert, CertRow, CertListParams } from '../../api/certs';
import { useAuth, hasRole } from '../../auth/AuthContext';
import { fmtTs } from '../../utils';

const PAGE_SIZE = 20;

export default function Certificates() {
  const { role } = useAuth();
  const canRevoke = hasRole(role, 'ca_operations');
  const navigate = useNavigate();

  const [certs, setCerts] = useState<CertRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revokedFilter, setRevokedFilter] = useState<string>('');

  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [revokeReason, setRevokeReason] = useState('unspecified');
  const [revoking, setRevoking] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: CertListParams = {
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
      };
      if (revokedFilter === 'revoked') params.revoked = true;
      if (revokedFilter === 'valid') params.revoked = false;
      const result = await listCerts(params);
      setCerts(result.certs);
      setTotal(result.total ?? result.certs.length);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load certificates');
    } finally {
      setLoading(false);
    }
  }, [page, revokedFilter]);

  useEffect(() => { load(); }, [load]);

  async function handleRevoke() {
    if (!revokeId) return;
    setRevoking(true);
    try {
      await revokeCert(revokeId, revokeReason);
      setRevokeId(null);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Revocation failed');
    } finally {
      setRevoking(false);
    }
  }

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Title headingLevel="h1">Certificates</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <select
                value={revokedFilter}
                onChange={e => { setRevokedFilter(e.target.value); setPage(1); }}
                style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px', fontSize: 'inherit' }}
              >
                <option value="">All</option>
                <option value="valid">Valid</option>
                <option value="revoked">Revoked</option>
              </select>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
        {loading && <Spinner />}
        {!loading && certs.length === 0 && (
          <EmptyState>
            <EmptyStateBody>No certificates found.</EmptyStateBody>
          </EmptyState>
        )}
        {!loading && certs.length > 0 && (
          <Table aria-label="Certificates">
            <Thead>
              <Tr>
                <Th>ID</Th>
                <Th>Subject DN</Th>
                <Th>Serial</Th>
                <Th>Not Before</Th>
                <Th>Not After</Th>
                <Th>Revoked</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {certs.map(cert => (
                <Tr key={cert.id}>
                  <Td>{cert.id}</Td>
                  <Td>{cert.subject_dn}</Td>
                  <Td>{cert.serial_number}</Td>
                  <Td>{fmtTs(cert.not_before)}</Td>
                  <Td>{fmtTs(cert.not_after)}</Td>
                  <Td>{cert.revoked_at ? cert.revocation_reason ?? 'yes' : '—'}</Td>
                  <Td>
                    {canRevoke && !cert.revoked_at && (
                      <Button variant="danger" size="sm" onClick={() => setRevokeId(cert.id)}>
                        Revoke
                      </Button>
                    )}{' '}
                    <Button variant="plain" size="sm" onClick={() => navigate(`/certs/${cert.id}`)}>View</Button>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
        <Pagination
          itemCount={total}
          perPage={PAGE_SIZE}
          page={page}
          onSetPage={(_e, p) => setPage(p)}
        />
      </PageSection>
      <Modal variant="small" isOpen={!!revokeId} onClose={() => setRevokeId(null)}>
        <ModalHeader title="Revoke Certificate" />
        <ModalBody>
          <p style={{ marginBottom: '1rem' }}>
            Are you sure you want to revoke certificate <strong>{revokeId}</strong>?
          </p>
          <label style={{ display: 'block', marginBottom: '4px', fontWeight: 500 }}>Reason</label>
          <select
            value={revokeReason}
            onChange={e => setRevokeReason(e.target.value)}
            style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px', fontSize: 'inherit', width: '100%' }}
          >
            <option value="unspecified">unspecified</option>
            <option value="keyCompromise">keyCompromise</option>
            <option value="affiliationChanged">affiliationChanged</option>
            <option value="superseded">superseded</option>
            <option value="cessationOfOperation">cessationOfOperation</option>
          </select>
        </ModalBody>
        <ModalFooter>
          <Button variant="danger" onClick={handleRevoke} isLoading={revoking} isDisabled={revoking}>
            Revoke
          </Button>
          <Button variant="link" onClick={() => setRevokeId(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>
    </>
  );
}
