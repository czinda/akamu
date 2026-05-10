import { useEffect, useState, useCallback } from 'react';
import {
  PageSection,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  ToolbarGroup,
  Button,
  TextInput,
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

interface FilterDraft {
  subject: string;
  serial: string;
  account_id: string;
  ca_id: string;
  status: string;
}

const EMPTY_DRAFT: FilterDraft = { subject: '', serial: '', account_id: '', ca_id: '', status: '' };

export default function Certificates() {
  const { role } = useAuth();
  const canRevoke = hasRole(role, 'ca_operations');
  const isCaRa = role === 'ca_ra';
  const navigate = useNavigate();

  const [certs, setCerts] = useState<CertRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [draft, setDraft] = useState<FilterDraft>(EMPTY_DRAFT);
  const [applied, setApplied] = useState<FilterDraft>(EMPTY_DRAFT);

  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [revokeReason, setRevokeReason] = useState(0);
  const [revoking, setRevoking] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: CertListParams = {
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
      };
      if (applied.subject)    params.subject    = applied.subject;
      if (applied.serial)     params.serial     = applied.serial;
      if (applied.account_id) params.account_id = applied.account_id;
      if (applied.ca_id)      params.ca_id      = applied.ca_id;
      if (applied.status)     params.status     = applied.status;
      const result = await listCerts(params);
      setCerts(result.certs);
      setTotal(result.total ?? result.certs.length);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load certificates');
    } finally {
      setLoading(false);
    }
  }, [page, applied]);

  useEffect(() => { load(); }, [load]);

  function handleSearch() {
    setApplied(draft);
    setPage(1);
  }

  function handleClear() {
    setDraft(EMPTY_DRAFT);
    setApplied(EMPTY_DRAFT);
    setPage(1);
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter') handleSearch();
  }

  async function handleRevoke() {
    if (!revokeId) return;
    setRevoking(true);
    try {
      await revokeCert(revokeId, revokeReason);
      setRevokeId(null);
      await load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Revocation failed');
    } finally {
      setRevoking(false);
    }
  }

  const inputStyle = { width: '160px' };

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Certificates</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarGroup>
              <ToolbarItem>
                <TextInput
                  placeholder="Subject DN"
                  value={draft.subject}
                  onChange={(_e, v) => setDraft(d => ({ ...d, subject: v }))}
                  onKeyDown={handleKeyDown}
                  style={inputStyle}
                  aria-label="Filter by subject DN"
                />
              </ToolbarItem>
              <ToolbarItem>
                <TextInput
                  placeholder="Serial"
                  value={draft.serial}
                  onChange={(_e, v) => setDraft(d => ({ ...d, serial: v }))}
                  onKeyDown={handleKeyDown}
                  style={inputStyle}
                  aria-label="Filter by serial"
                />
              </ToolbarItem>
              <ToolbarItem>
                <TextInput
                  placeholder="Account ID"
                  value={draft.account_id}
                  onChange={(_e, v) => setDraft(d => ({ ...d, account_id: v }))}
                  onKeyDown={handleKeyDown}
                  style={inputStyle}
                  aria-label="Filter by account ID"
                />
              </ToolbarItem>
              {!isCaRa && (
                <ToolbarItem>
                  <TextInput
                    placeholder="CA ID"
                    value={draft.ca_id}
                    onChange={(_e, v) => setDraft(d => ({ ...d, ca_id: v }))}
                    onKeyDown={handleKeyDown}
                    style={inputStyle}
                    aria-label="Filter by CA ID"
                  />
                </ToolbarItem>
              )}
              <ToolbarItem>
                <select
                  value={draft.status}
                  onChange={e => setDraft(d => ({ ...d, status: e.target.value }))}
                  style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px', fontSize: 'inherit' }}
                  aria-label="Filter by status"
                >
                  <option value="">All statuses</option>
                  <option value="valid">valid</option>
                  <option value="revoked">revoked</option>
                </select>
              </ToolbarItem>
              <ToolbarItem>
                <Button variant="primary" onClick={handleSearch}>Search</Button>
              </ToolbarItem>
              <ToolbarItem>
                <Button variant="link" onClick={handleClear}>Clear</Button>
              </ToolbarItem>
            </ToolbarGroup>
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
                <Th>Status</Th>
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
                  <Td>{cert.revoked_at ? `revoked (${cert.revocation_reason ?? 'unspecified'})` : cert.status}</Td>
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
            onChange={e => setRevokeReason(parseInt(e.target.value, 10))}
            style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px', fontSize: 'inherit', width: '100%' }}
          >
            <option value={0}>unspecified</option>
            <option value={1}>keyCompromise</option>
            <option value={3}>affiliationChanged</option>
            <option value={4}>superseded</option>
            <option value={5}>cessationOfOperation</option>
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
