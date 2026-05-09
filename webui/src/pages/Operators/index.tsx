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
  Label,
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
  listOperators,
  createOperator,
  updateOperator,
  activateOperator,
  deactivateOperator,
  unlockOperator,
  OperatorRow,
} from '../../api/operators';

const selectStyle: React.CSSProperties = {
  padding: '6px 8px',
  border: '1px solid #ccc',
  borderRadius: '4px',
  fontSize: 'inherit',
  width: '100%',
};

export default function Operators() {
  const [operators, setOperators] = useState<OperatorRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editRow, setEditRow] = useState<OperatorRow | null>(null);
  const [saving, setSaving] = useState(false);

  const [formName, setFormName] = useState('');
  const [formRole, setFormRole] = useState('auditor');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listOperators();
      setOperators(result.operators);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load operators');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  function openCreate() {
    setFormName('');
    setFormRole('auditor');
    setCreateOpen(true);
  }

  function openEdit(op: OperatorRow) {
    setEditRow(op);
    setFormRole(op.role);
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      await createOperator({ name: formName, role: formRole });
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
      await updateOperator(editRow.id, { role: formRole });
      setEditRow(null);
      load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Update failed');
    } finally {
      setSaving(false);
    }
  }

  async function handleAction(action: () => Promise<void>) {
    setSaving(true);
    try {
      await action();
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Action failed');
    } finally {
      setSaving(false);
    }
  }

  const roleField = (
    <FormGroup label="Role" isRequired fieldId="op-role">
      <select
        id="op-role"
        value={formRole}
        onChange={e => setFormRole(e.target.value)}
        style={selectStyle}
      >
        <option value="administrator">administrator</option>
        <option value="ca_operations">ca_operations</option>
        <option value="ca_ra">ca_ra</option>
        <option value="auditor">auditor</option>
      </select>
    </FormGroup>
  );

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Title headingLevel="h1">Operators</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <Button variant="primary" onClick={openCreate}>Create Operator</Button>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
        {loading && <Spinner />}
        {!loading && operators.length === 0 && (
          <EmptyState><EmptyStateBody>No operators found.</EmptyStateBody></EmptyState>
        )}
        {!loading && operators.length > 0 && (
          <Table aria-label="Operators">
            <Thead>
              <Tr>
                <Th>Name</Th>
                <Th>Role</Th>
                <Th>Status</Th>
                <Th>Locked</Th>
                <Th>Last Seen</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {operators.map(op => (
                <Tr key={op.id}>
                  <Td>{op.name}</Td>
                  <Td>{op.role}</Td>
                  <Td>
                    <Label color={op.active ? 'green' : 'red'}>{op.active ? 'active' : 'inactive'}</Label>
                  </Td>
                  <Td>{op.locked ? <Label color="orange">locked</Label> : '—'}</Td>
                  <Td>{op.last_seen_at ?? '—'}</Td>
                  <Td>
                    <Button variant="secondary" size="sm" onClick={() => openEdit(op)}>Edit</Button>{' '}
                    {op.active
                      ? <Button variant="warning" size="sm" isDisabled={saving} onClick={() => handleAction(() => deactivateOperator(op.id))}>Deactivate</Button>
                      : <Button variant="secondary" size="sm" isDisabled={saving} onClick={() => handleAction(() => activateOperator(op.id))}>Activate</Button>
                    }{' '}
                    {op.locked && (
                      <Button variant="secondary" size="sm" isDisabled={saving} onClick={() => handleAction(() => unlockOperator(op.id))}>Unlock</Button>
                    )}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </PageSection>
      <Modal variant="medium" isOpen={createOpen} onClose={() => setCreateOpen(false)}>
        <ModalHeader title="Create Operator" />
        <ModalBody>
          <Form id="op-create-form" onSubmit={handleCreate}>
            <FormGroup label="Name" isRequired fieldId="op-name">
              <TextInput id="op-name" value={formName} onChange={(_e, v) => setFormName(v)} isRequired />
            </FormGroup>
            {roleField}
          </Form>
        </ModalBody>
        <ModalFooter>
          <Button form="op-create-form" type="submit" variant="primary" isLoading={saving} isDisabled={saving}>Create</Button>
          <Button variant="link" onClick={() => setCreateOpen(false)}>Cancel</Button>
        </ModalFooter>
      </Modal>
      <Modal variant="medium" isOpen={!!editRow} onClose={() => setEditRow(null)}>
        <ModalHeader title={`Edit Operator: ${editRow?.name}`} />
        <ModalBody>
          <Form id="op-edit-form" onSubmit={handleUpdate}>
            {roleField}
          </Form>
        </ModalBody>
        <ModalFooter>
          <Button form="op-edit-form" type="submit" variant="primary" isLoading={saving} isDisabled={saving}>Save</Button>
          <Button variant="link" onClick={() => setEditRow(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>
    </>
  );
}
