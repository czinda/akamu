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
  Pagination,
  FormSelect,
  FormSelectOption,
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
import { useNavigate } from 'react-router-dom';
import { useAuth, hasRole } from '../../auth/AuthContext';
import { fmtTs } from '../../utils';
import { ObjLink } from '../../components/ObjLink';
import { errorMessage } from '../../api/client';

const PAGE_SIZE = 20;

export default function Accounts() {
  const { role } = useAuth();
  const canWrite = hasRole(role, 'ca_ra');
  const navigate = useNavigate();

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
      setError(errorMessage(e, 'Failed to load accounts'));
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
      await load();
    } catch (e: unknown) {
      setError(errorMessage(e, 'Deactivation failed'));
    } finally {
      setDeactivating(false);
    }
  }

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Accounts</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <FormSelect
                value={statusFilter}
                onChange={(_e, v) => { setStatusFilter(v); setPage(1); }}
                aria-label="Filter by status"
              >
                <FormSelectOption value="" label="All statuses" />
                <FormSelectOption value="valid" label="valid" />
                <FormSelectOption value="deactivated" label="deactivated" />
                <FormSelectOption value="revoked" label="revoked" />
              </FormSelect>
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
                <Th>Updated</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {accounts.map(acct => (
                <Tr key={acct.id}>
                  <Td>{acct.id}</Td>
                  <Td>{acct.status}</Td>
                  <Td><ObjLink type="ca" id={acct.ca_id} /></Td>
                  <Td>{fmtTs(acct.created)}</Td>
                  <Td>{fmtTs(acct.updated)}</Td>
                  <Td>
                    {canWrite && acct.status === 'valid' && (
                      <Button variant="danger" size="sm" onClick={() => setDeactivateId(acct.id)}>
                        Deactivate
                      </Button>
                    )}{' '}
                    <Button variant="plain" size="sm" onClick={() => navigate(`/accounts/${acct.id}`)}>View</Button>
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
