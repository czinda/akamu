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
  Form,
  FormGroup,
  TextInput,
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
  listDelegations,
  createDelegation,
  updateDelegation,
  deleteDelegation,
  DelegationRow,
  DelegationOptions,
} from '../../api/delegations';

const PAGE_SIZE = 20;

export default function Delegations() {
  const [delegations, setDelegations] = useState<DelegationRow[]>([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editRow, setEditRow] = useState<DelegationRow | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const [formAccountId, setFormAccountId] = useState('');
  const [formTemplate, setFormTemplate] = useState('');
  const [formCnameMap, setFormCnameMap] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listDelegations({ limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE });
      setDelegations(result.delegations);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load delegations');
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => { load(); }, [load]);

  function openCreate() {
    setFormAccountId('');
    setFormTemplate('');
    setFormCnameMap('');
    setCreateOpen(true);
  }

  function openEdit(row: DelegationRow) {
    setEditRow(row);
    setFormAccountId(row.account_id);
    setFormTemplate(row.csr_template);
    setFormCnameMap(row.cname_map ?? '');
  }

  function buildOpts(): DelegationOptions {
    const opts: DelegationOptions = { account_id: formAccountId, csr_template: formTemplate };
    if (formCnameMap) {
      try { opts.cname_map = JSON.parse(formCnameMap); } catch { /* ignore */ }
    }
    return opts;
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      await createDelegation(buildOpts());
      setCreateOpen(false);
      load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Create failed');
    } finally {
      setSaving(false);
    }
  }

  async function handleUpdate(e: React.FormEvent) {
    e.preventDefault();
    if (!editRow) return;
    setSaving(true);
    try {
      await updateDelegation(editRow.id, buildOpts());
      setEditRow(null);
      load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Update failed');
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!deleteId) return;
    setSaving(true);
    try {
      await deleteDelegation(deleteId);
      setDeleteId(null);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Delete failed');
    } finally {
      setSaving(false);
    }
  }

  const formFields = (
    <>
      <FormGroup label="Account ID" isRequired fieldId="del-account-id">
        <TextInput id="del-account-id" value={formAccountId} onChange={(_e, v) => setFormAccountId(v)} isRequired />
      </FormGroup>
      <FormGroup label="CSR Template" isRequired fieldId="del-template">
        <TextInput id="del-template" value={formTemplate} onChange={(_e, v) => setFormTemplate(v)} isRequired />
      </FormGroup>
      <FormGroup label="CNAME Map (JSON, optional)" fieldId="del-cname">
        <TextInput id="del-cname" value={formCnameMap} onChange={(_e, v) => setFormCnameMap(v)} />
      </FormGroup>
    </>
  );

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Title headingLevel="h1">Delegations</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <Button variant="primary" onClick={openCreate}>Create Delegation</Button>
            </ToolbarItem>
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
                  <Td>{d.account_id}</Td>
                  <Td>{d.csr_template}</Td>
                  <Td>{d.created_at}</Td>
                  <Td>
                    <Button variant="secondary" size="sm" onClick={() => openEdit(d)}>Edit</Button>{' '}
                    <Button variant="danger" size="sm" onClick={() => setDeleteId(d.id)}>Delete</Button>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
        <Pagination itemCount={delegations.length} perPage={PAGE_SIZE} page={page} onSetPage={(_e, p) => setPage(p)} />
      </PageSection>
      <Modal variant="medium" isOpen={createOpen} onClose={() => setCreateOpen(false)}>
        <ModalHeader title="Create Delegation" />
        <ModalBody>
          <Form id="del-create-form" onSubmit={handleCreate}>{formFields}</Form>
        </ModalBody>
        <ModalFooter>
          <Button form="del-create-form" type="submit" variant="primary" isLoading={saving} isDisabled={saving}>Create</Button>
          <Button variant="link" onClick={() => setCreateOpen(false)}>Cancel</Button>
        </ModalFooter>
      </Modal>
      <Modal variant="medium" isOpen={!!editRow} onClose={() => setEditRow(null)}>
        <ModalHeader title={`Edit Delegation ${editRow?.id}`} />
        <ModalBody>
          <Form id="del-edit-form" onSubmit={handleUpdate}>{formFields}</Form>
        </ModalBody>
        <ModalFooter>
          <Button form="del-edit-form" type="submit" variant="primary" isLoading={saving} isDisabled={saving}>Save</Button>
          <Button variant="link" onClick={() => setEditRow(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>
      <Modal variant="small" isOpen={!!deleteId} onClose={() => setDeleteId(null)}>
        <ModalHeader title="Delete Delegation" />
        <ModalBody>
          <p>Delete delegation <strong>{deleteId}</strong>?</p>
        </ModalBody>
        <ModalFooter>
          <Button variant="danger" onClick={handleDelete} isLoading={saving} isDisabled={saving}>Delete</Button>
          <Button variant="link" onClick={() => setDeleteId(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>
    </>
  );
}
