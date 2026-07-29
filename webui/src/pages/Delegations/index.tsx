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
import { listDelegations, deleteDelegation, DelegationRow } from '../../api/delegations';
import { fmtTs } from '../../utils';
import { ObjLink } from '../../components/ObjLink';
import { useAuth, hasRole } from '../../auth/AuthContext';
import { errorMessage } from '../../api/client';

const PAGE_SIZE = 20;

function csrSummary(tmpl: unknown): string {
  if (!tmpl) return '—';
  if (typeof tmpl === 'string') return tmpl.slice(0, 60);
  const s = JSON.stringify(tmpl);
  return s.length > 60 ? s.slice(0, 57) + '…' : s;
}

export default function Delegations() {
  const navigate = useNavigate();
  const { role } = useAuth();
  const canWrite = hasRole(role, 'ca_operations');
  const [delegations, setDelegations] = useState<DelegationRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listDelegations({ limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE });
      setDelegations(result.delegations);
      setTotal(result.total);
    } catch (e: unknown) {
      setError(errorMessage(e, 'Failed to load delegations'));
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => { load(); }, [load]);

  async function handleDelete() {
    if (!deleteId) return;
    setSaving(true);
    try {
      await deleteDelegation(deleteId);
      setDeleteId(null);
      await load();
    } catch (e: unknown) {
      setError(errorMessage(e, 'Delete failed'));
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Delegations</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            {canWrite && (
              <ToolbarItem>
                <Button variant="primary" onClick={() => navigate('/delegations/new')}>Create Delegation</Button>
              </ToolbarItem>
            )}
          </ToolbarContent>
        </Toolbar>
        {loading && <Spinner />}
        {!loading && delegations.length === 0 && (
          <EmptyState><EmptyStateBody>No delegations found.</EmptyStateBody></EmptyState>
        )}
        {!loading && delegations.length > 0 && (
          <Table aria-label="Delegations">
            <Thead>
              <Tr>
                <Th>ID</Th>
                <Th>Account</Th>
                <Th>CSR Template</Th>
                <Th>Created</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {delegations.map(d => (
                <Tr key={d.id}>
                  <Td>{d.id}</Td>
                  <Td><ObjLink type="account" id={d.account_id} /></Td>
                  <Td style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: '#555' }}>{csrSummary(d.csr_template)}</Td>
                  <Td>{fmtTs(d.created)}</Td>
                  <Td>
                    <Button variant="plain" size="sm" onClick={() => navigate(`/delegations/${d.id}`)}>View</Button>
                    {canWrite && <>{' '}<Button variant="secondary" size="sm" onClick={() => navigate(`/delegations/${d.id}/edit`)}>Edit</Button></>}
                    {canWrite && <>{' '}<Button variant="danger" size="sm" onClick={() => setDeleteId(d.id)}>Delete</Button></>}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
        <Pagination itemCount={total} perPage={PAGE_SIZE} page={page} onSetPage={(_e, p) => setPage(p)} />
      </PageSection>
      <Modal variant="small" isOpen={!!deleteId} onClose={() => setDeleteId(null)}>
        <ModalHeader title="Delete Delegation" />
        <ModalBody>
          <p>Delete delegation <strong>{deleteId}</strong>? This cannot be undone.</p>
        </ModalBody>
        <ModalFooter>
          <Button variant="danger" onClick={handleDelete} isLoading={saving} isDisabled={saving}>Delete</Button>
          <Button variant="link" onClick={() => setDeleteId(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>
    </>
  );
}
