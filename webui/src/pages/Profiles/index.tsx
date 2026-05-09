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
} from '@patternfly/react-core';
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
} from '@patternfly/react-table';
import { listProfiles, createProfile, updateProfile, deleteProfile, ProfileEntry } from '../../api/profiles';
import { useAuth, hasRole } from '../../auth/AuthContext';

export default function Profiles() {
  const { role } = useAuth();
  const isAdmin = hasRole(role, 'administrator');

  const [profiles, setProfiles] = useState<ProfileEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editEntry, setEditEntry] = useState<ProfileEntry | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [formId, setFormId] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formValidityDays, setFormValidityDays] = useState('365');
  const [formHashAlg, setFormHashAlg] = useState('sha256');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listProfiles();
      setProfiles(result.profiles);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load profiles');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  function openCreate() {
    setFormId('');
    setFormDescription('');
    setFormValidityDays('365');
    setFormHashAlg('sha256');
    setCreateOpen(true);
  }

  function openEdit(p: ProfileEntry) {
    setEditEntry(p);
    setFormDescription(p.description);
    setFormValidityDays(String(p.validity_days ?? 365));
    setFormHashAlg(p.hash_alg ?? 'sha256');
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      await createProfile(formId, {
        description: formDescription,
        validity_days: parseInt(formValidityDays, 10),
        hash_alg: formHashAlg,
      });
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
    if (!editEntry) return;
    setSaving(true);
    try {
      await updateProfile(editEntry.id, {
        description: formDescription,
        validity_days: parseInt(formValidityDays, 10),
        hash_alg: formHashAlg,
      });
      setEditEntry(null);
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
      await deleteProfile(deleteId);
      setDeleteId(null);
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
        <Title headingLevel="h1">Profiles</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        {isAdmin && (
          <Toolbar>
            <ToolbarContent>
              <ToolbarItem>
                <Button variant="primary" onClick={openCreate}>Create Profile</Button>
              </ToolbarItem>
            </ToolbarContent>
          </Toolbar>
        )}
        {loading && <Spinner />}
        {!loading && profiles.length === 0 && (
          <EmptyState><EmptyStateBody>No profiles found.</EmptyStateBody></EmptyState>
        )}
        {!loading && profiles.length > 0 && (
          <Table aria-label="Profiles">
            <Thead>
              <Tr>
                <Th>ID</Th>
                <Th>Description</Th>
                <Th>Validity (days)</Th>
                <Th>Hash Alg</Th>
                {isAdmin && <Th>Actions</Th>}
              </Tr>
            </Thead>
            <Tbody>
              {profiles.map(p => (
                <Tr key={p.id}>
                  <Td>{p.id}</Td>
                  <Td>{p.description || '—'}</Td>
                  <Td>{p.validity_days ?? '—'}</Td>
                  <Td>{p.hash_alg ?? '—'}</Td>
                  {isAdmin && (
                    <Td>
                      <Button variant="secondary" size="sm" onClick={() => openEdit(p)}>Edit</Button>{' '}
                      <Button variant="danger" size="sm" onClick={() => setDeleteId(p.id)}>Delete</Button>
                    </Td>
                  )}
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </PageSection>
      <Modal variant="medium" isOpen={createOpen} onClose={() => setCreateOpen(false)}>
        <ModalHeader title="Create Profile" />
        <ModalBody>
          <Form id="profile-create-form" onSubmit={handleCreate}>
            <FormGroup label="Profile ID" isRequired fieldId="profile-id">
              <TextInput id="profile-id" value={formId} onChange={(_e, v) => setFormId(v)} isRequired />
            </FormGroup>
            <FormGroup label="Description" fieldId="profile-desc">
              <TextInput id="profile-desc" value={formDescription} onChange={(_e, v) => setFormDescription(v)} />
            </FormGroup>
            <FormGroup label="Validity (days)" isRequired fieldId="profile-validity">
              <TextInput id="profile-validity" type="number" value={formValidityDays} onChange={(_e, v) => setFormValidityDays(v)} isRequired />
            </FormGroup>
            <FormGroup label="Hash Algorithm" isRequired fieldId="profile-hash">
              <select id="profile-hash" value={formHashAlg} onChange={e => setFormHashAlg(e.target.value)}
                style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px', fontSize: 'inherit', width: '100%' }}>
                <option value="sha256">sha256</option>
                <option value="sha384">sha384</option>
                <option value="sha512">sha512</option>
              </select>
            </FormGroup>
          </Form>
        </ModalBody>
        <ModalFooter>
          <Button form="profile-create-form" type="submit" variant="primary" isLoading={saving} isDisabled={saving}>Create</Button>
          <Button variant="link" onClick={() => setCreateOpen(false)}>Cancel</Button>
        </ModalFooter>
      </Modal>
      <Modal variant="medium" isOpen={!!editEntry} onClose={() => setEditEntry(null)}>
        <ModalHeader title={`Edit Profile: ${editEntry?.id}`} />
        <ModalBody>
          <Form id="profile-edit-form" onSubmit={handleUpdate}>
            <FormGroup label="Description" fieldId="profile-edit-desc">
              <TextInput id="profile-edit-desc" value={formDescription} onChange={(_e, v) => setFormDescription(v)} />
            </FormGroup>
            <FormGroup label="Validity (days)" isRequired fieldId="profile-edit-validity">
              <TextInput id="profile-edit-validity" type="number" value={formValidityDays} onChange={(_e, v) => setFormValidityDays(v)} isRequired />
            </FormGroup>
            <FormGroup label="Hash Algorithm" isRequired fieldId="profile-edit-hash">
              <select id="profile-edit-hash" value={formHashAlg} onChange={e => setFormHashAlg(e.target.value)}
                style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px', fontSize: 'inherit', width: '100%' }}>
                <option value="sha256">sha256</option>
                <option value="sha384">sha384</option>
                <option value="sha512">sha512</option>
              </select>
            </FormGroup>
          </Form>
        </ModalBody>
        <ModalFooter>
          <Button form="profile-edit-form" type="submit" variant="primary" isLoading={saving} isDisabled={saving}>Save</Button>
          <Button variant="link" onClick={() => setEditEntry(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>
      <Modal variant="small" isOpen={!!deleteId} onClose={() => setDeleteId(null)}>
        <ModalHeader title="Delete Profile" />
        <ModalBody>
          <p>Delete profile <strong>{deleteId}</strong>?</p>
        </ModalBody>
        <ModalFooter>
          <Button variant="danger" onClick={handleDelete} isLoading={saving} isDisabled={saving}>Delete</Button>
          <Button variant="link" onClick={() => setDeleteId(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>
    </>
  );
}
