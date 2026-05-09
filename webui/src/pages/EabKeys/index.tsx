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
import { useNavigate } from 'react-router-dom';
import { listEab, createEab, deleteEab, EabKeyRow } from '../../api/eab';
import { fmtTs } from '../../utils';

const PAGE_SIZE = 20;

export default function EabKeys() {
  const navigate = useNavigate();
  const [keys, setKeys] = useState<EabKeyRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [deleteKid, setDeleteKid] = useState<string | null>(null);
  const [newKid, setNewKid] = useState('');
  const [newKey, setNewKey] = useState('');
  const [newAlg, setNewAlg] = useState('sha256');
  const [newGrants, setNewGrants] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listEab({ limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE });
      setKeys(result.eab_keys);
      setTotal(result.total);
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
      const grants = newGrants.trim()
        ? newGrants.split(/[\s,]+/).map(s => s.trim()).filter(Boolean)
        : undefined;
      await createEab({ kid: newKid, hmac_key_b64u: newKey, alg: newAlg, profile_grants: grants });
      setCreateOpen(false);
      setNewKid('');
      setNewKey('');
      setNewAlg('sha256');
      setNewGrants('');
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
                <Th>Bound To</Th>
                <Th>Used At</Th>
                <Th>Profile Grants</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {keys.map(k => (
                <Tr key={k.kid}>
                  <Td>{k.kid}</Td>
                  <Td>{fmtTs(k.created)}</Td>
                  <Td>{k.bound_principal ?? '—'}</Td>
                  <Td>{fmtTs(k.used_at)}</Td>
                  <Td>{k.profile_grants?.join(', ') ?? '—'}</Td>
                  <Td>
                    <Button variant="danger" size="sm" onClick={() => setDeleteKid(k.kid)}>Delete</Button>{' '}
                    <Button variant="plain" size="sm" onClick={() => navigate(`/eab/${k.kid}`)}>View</Button>
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
      <Modal variant="small" isOpen={createOpen} onClose={() => setCreateOpen(false)}>
        <ModalHeader title="Create EAB Key" />
        <ModalBody>
          <Form id="eab-create-form" onSubmit={handleCreate}>
            <FormGroup label="Key ID" isRequired fieldId="eab-new-kid">
              <TextInput id="eab-new-kid" value={newKid} onChange={(_e, v) => setNewKid(v)} isRequired />
            </FormGroup>
            <FormGroup label="HMAC Key (base64url)" isRequired fieldId="eab-new-key">
              <TextInput id="eab-new-key" value={newKey} onChange={(_e, v) => setNewKey(v)} isRequired />
            </FormGroup>
            <FormGroup label="HMAC Algorithm" isRequired fieldId="eab-new-alg">
              <select id="eab-new-alg" value={newAlg} onChange={e => setNewAlg(e.target.value)}
                style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px', fontSize: 'inherit', width: '100%' }}>
                <option value="sha256">sha256</option>
                <option value="sha384">sha384</option>
                <option value="sha512">sha512</option>
              </select>
            </FormGroup>
            <FormGroup label="Profile Grants (comma-separated, optional)" fieldId="eab-new-grants"
              helperText="Restrict this key to specific profiles. Leave empty for unrestricted access.">
              <TextInput id="eab-new-grants" value={newGrants} onChange={(_e, v) => setNewGrants(v)}
                placeholder="profile-a, profile-b" />
            </FormGroup>
          </Form>
        </ModalBody>
        <ModalFooter>
          <Button variant="primary" form="eab-create-form" type="submit" isLoading={saving} isDisabled={saving}>Create</Button>
          <Button variant="link" onClick={() => setCreateOpen(false)}>Cancel</Button>
        </ModalFooter>
      </Modal>
      <Modal variant="small" isOpen={!!deleteKid} onClose={() => setDeleteKid(null)}>
        <ModalHeader title="Delete EAB Key" />
        <ModalBody>
          <p>Delete EAB key <strong>{deleteKid}</strong>?</p>
        </ModalBody>
        <ModalFooter>
          <Button variant="danger" onClick={handleDelete} isLoading={saving} isDisabled={saving}>Delete</Button>
          <Button variant="link" onClick={() => setDeleteKid(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>
    </>
  );
}
