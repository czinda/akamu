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
import { listEab, createEab, deleteEab, EabKeyRow } from '../../api/eab';

const PAGE_SIZE = 20;

export default function EabKeys() {
  const [keys, setKeys] = useState<EabKeyRow[]>([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [deleteKid, setDeleteKid] = useState<string | null>(null);
  const [newKid, setNewKid] = useState('');
  const [newKey, setNewKey] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listEab({ limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE });
      setKeys(result.eab_keys);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load EAB keys');
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => { load(); }, [load]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      await createEab({ kid: newKid, hmac_key_b64u: newKey });
      setCreateOpen(false);
      setNewKid('');
      setNewKey('');
      load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Create failed');
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!deleteKid) return;
    setSaving(true);
    try {
      await deleteEab(deleteKid);
      setDeleteKid(null);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Delete failed');
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Title headingLevel="h1">EAB Keys</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <Button variant="primary" onClick={() => setCreateOpen(true)}>Create EAB Key</Button>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
        {loading && <Spinner />}
        {!loading && keys.length === 0 && (
          <EmptyState><EmptyStateBody>No EAB keys found.</EmptyStateBody></EmptyState>
        )}
        {!loading && keys.length > 0 && (
          <Table aria-label="EAB Keys">
            <Thead>
              <Tr>
                <Th>KID</Th>
                <Th>Created</Th>
                <Th>Used At</Th>
                <Th>Profile Grants</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {keys.map(k => (
                <Tr key={k.kid}>
                  <Td>{k.kid}</Td>
                  <Td>{new Date(k.created * 1000).toISOString()}</Td>
                  <Td>{k.used_at ? new Date(k.used_at * 1000).toISOString() : '—'}</Td>
                  <Td>{k.profile_grants?.join(', ') ?? '—'}</Td>
                  <Td>
                    <Button variant="danger" size="sm" onClick={() => setDeleteKid(k.kid)}>Delete</Button>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
        <Pagination
          itemCount={keys.length}
          perPage={PAGE_SIZE}
          page={page}
          onSetPage={(_e, p) => setPage(p)}
        />
      </PageSection>
      <Modal
        variant={ModalVariant.small}
        title="Create EAB Key"
        isOpen={createOpen}
        onClose={() => setCreateOpen(false)}
        actions={[
          <Button key="save" variant="primary" form="eab-create-form" type="submit" isLoading={saving} isDisabled={saving}>
            Create
          </Button>,
          <Button key="cancel" variant="link" onClick={() => setCreateOpen(false)}>Cancel</Button>,
        ]}
      >
        <Form id="eab-create-form" onSubmit={handleCreate}>
          <FormGroup label="Key ID" isRequired fieldId="eab-new-kid">
            <TextInput id="eab-new-kid" value={newKid} onChange={(_e, v) => setNewKid(v)} isRequired />
          </FormGroup>
          <FormGroup label="HMAC Key (base64url)" isRequired fieldId="eab-new-key">
            <TextInput id="eab-new-key" value={newKey} onChange={(_e, v) => setNewKey(v)} isRequired />
          </FormGroup>
        </Form>
      </Modal>
      <Modal
        variant={ModalVariant.small}
        title="Delete EAB Key"
        isOpen={!!deleteKid}
        onClose={() => setDeleteKid(null)}
        actions={[
          <Button key="confirm" variant="danger" onClick={handleDelete} isLoading={saving} isDisabled={saving}>
            Delete
          </Button>,
          <Button key="cancel" variant="link" onClick={() => setDeleteKid(null)}>Cancel</Button>,
        ]}
      >
        <p>Delete EAB key <strong>{deleteKid}</strong>?</p>
      </Modal>
    </>
  );
}
