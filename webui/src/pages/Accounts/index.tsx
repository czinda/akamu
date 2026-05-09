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
import {
  listAccounts,
  deactivateAccount,
  AccountRow,
  AccountListParams,
} from '../../api/accounts';
import { useAuth, hasRole } from '../../auth/AuthContext';

const PAGE_SIZE = 20;

export default function Accounts() {
  const { role } = useAuth();
  const canWrite = hasRole(role, 'ca_ra');

  const [accounts, setAccounts] = useState<AccountRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [deactivateId, setDeactivateId] = useState<string | null>(null);
  const [deactivating, setDeactivating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: AccountListParams = { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE };
      if (statusFilter) params.status = statusFilter;
      const result = await listAccounts(params);
      setAccounts(result.accounts);
      setTotal(result.total ?? result.accounts.length);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load accounts');
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter]);

  useEffect(() => { load(); }, [load]);

  async function handleDeactivate() {
    if (!deactivateId) return;
    setDeactivating(true);
    try {
      await deactivateAccount(deactivateId);
      setDeactivateId(null);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Deactivation failed');
    } finally {
      setDeactivating(false);
    }
  }

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Title headingLevel="h1">Accounts</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <select
                value={statusFilter}
                onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
                style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px', fontSize: 'inherit' }}
              >
                <option value="">All statuses</option>
                <option value="valid">valid</option>
                <option value="deactivated">deactivated</option>
                <option value="revoked">revoked</option>
              </select>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
        {loading && <Spinner />}
        {!loading && accounts.length === 0 && (
          <EmptyState><EmptyStateBody>No accounts found.</EmptyStateBody></EmptyState>
        )}
        {!loading && accounts.length > 0 && (
          <Table aria-label="Accounts">
            <Thead>
              <Tr>
                <Th>ID</Th>
                <Th>Status</Th>
                <Th>CA</Th>
                <Th>Created</Th>
                <Th>Last Seen</Th>
                {canWrite && <Th>Actions</Th>}
              </Tr>
            </Thead>
            <Tbody>
              {accounts.map(acct => (
                <Tr key={acct.id}>
                  <Td>{acct.id}</Td>
                  <Td>{acct.status}</Td>
                  <Td>{acct.ca_id}</Td>
                  <Td>{acct.created_at}</Td>
                  <Td>{acct.last_seen_at ?? '—'}</Td>
                  {canWrite && (
                    <Td>
                      {acct.status === 'valid' && (
                        <Button variant="danger" size="sm" onClick={() => setDeactivateId(acct.id)}>
                          Deactivate
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
      <Modal variant="small" isOpen={!!deactivateId} onClose={() => setDeactivateId(null)}>
        <ModalHeader title="Deactivate Account" />
        <ModalBody>
          <p>Deactivate account <strong>{deactivateId}</strong>?</p>
        </ModalBody>
        <ModalFooter>
          <Button variant="danger" onClick={handleDeactivate} isLoading={deactivating} isDisabled={deactivating}>
            Deactivate
          </Button>
          <Button variant="link" onClick={() => setDeactivateId(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>
    </>
  );
}
