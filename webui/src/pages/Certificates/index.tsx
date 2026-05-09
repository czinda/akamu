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
  Select,
  SelectOption,
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
import { listCerts, revokeCert, CertRow, CertListParams } from '../../api/certs';
import { useAuth, hasRole } from '../../auth/AuthContext';

const PAGE_SIZE = 20;

export default function Certificates() {
  const { role } = useAuth();
  const canRevoke = hasRole(role, 'ca_operations');

  const [certs, setCerts] = useState<CertRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revokedFilter, setRevokedFilter] = useState<string>('');
  const [filterOpen, setFilterOpen] = useState(false);

  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [revokeReason, setRevokeReason] = useState('unspecified');
  const [reasonOpen, setReasonOpen] = useState(false);
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
              <Select
                isOpen={filterOpen}
                onToggle={(_e, v) => setFilterOpen(v)}
                onSelect={(_e, v) => { setRevokedFilter(v as string); setFilterOpen(false); setPage(1); }}
                selections={revokedFilter || 'All'}
                placeholderText="All"
              >
                <SelectOption value="">All</SelectOption>
                <SelectOption value="valid">Valid</SelectOption>
                <SelectOption value="revoked">Revoked</SelectOption>
              </Select>
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
                {canRevoke && <Th>Actions</Th>}
              </Tr>
            </Thead>
            <Tbody>
              {certs.map(cert => (
                <Tr key={cert.id}>
                  <Td>{cert.id}</Td>
                  <Td>{cert.subject_dn}</Td>
                  <Td>{cert.serial}</Td>
                  <Td>{cert.not_before}</Td>
                  <Td>{cert.not_after}</Td>
                  <Td>{cert.revoked_at ? cert.revocation_reason ?? 'yes' : '—'}</Td>
                  {canRevoke && (
                    <Td>
                      {!cert.revoked_at && (
                        <Button variant="danger" size="sm" onClick={() => setRevokeId(cert.id)}>
                          Revoke
                        </Button>
                      )}
                    </Td>
                  )}
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
      <Modal
        variant={ModalVariant.small}
        title="Revoke Certificate"
        isOpen={!!revokeId}
        onClose={() => setRevokeId(null)}
        actions={[
          <Button key="confirm" variant="danger" onClick={handleRevoke} isLoading={revoking} isDisabled={revoking}>
            Revoke
          </Button>,
          <Button key="cancel" variant="link" onClick={() => setRevokeId(null)}>
            Cancel
          </Button>,
        ]}
      >
        <p>Are you sure you want to revoke certificate <strong>{revokeId}</strong>?</p>
        <Select
          isOpen={reasonOpen}
          onToggle={(_e, v) => setReasonOpen(v)}
          onSelect={(_e, v) => { setRevokeReason(v as string); setReasonOpen(false); }}
          selections={revokeReason}
        >
          <SelectOption value="unspecified">unspecified</SelectOption>
          <SelectOption value="keyCompromise">keyCompromise</SelectOption>
          <SelectOption value="affiliationChanged">affiliationChanged</SelectOption>
          <SelectOption value="superseded">superseded</SelectOption>
          <SelectOption value="cessationOfOperation">cessationOfOperation</SelectOption>
        </Select>
      </Modal>
    </>
  );
}
