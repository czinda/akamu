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
  TextArea,
} from '@patternfly/react-core';
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
} from '@patternfly/react-table';
import { listProfiles, createProfile, updateProfile, deleteProfile } from '../../api/profiles';
import { useAuth, hasRole } from '../../auth/AuthContext';

interface ProfileEntry { id: string; config: Record<string, unknown> }

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
  const [formConfig, setFormConfig] = useState('{}');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listProfiles();
      const entries: ProfileEntry[] = Object.entries(result.providers).map(([id, config]) => ({
        id,
        config: config as Record<string, unknown>,
      }));
      setProfiles(entries);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load profiles');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  function openCreate() {
    setFormId('');
    setFormConfig('{}');
    setCreateOpen(true);
  }

  function openEdit(p: ProfileEntry) {
    setEditEntry(p);
    setFormConfig(JSON.stringify(p.config, null, 2));
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      const parsed = JSON.parse(formConfig);
      await createProfile(formId, parsed);
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
      const parsed = JSON.parse(formConfig);
      await updateProfile(editEntry.id, parsed);
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
                <Th>Config</Th>
                {isAdmin && <Th>Actions</Th>}
              </Tr>
            </Thead>
            <Tbody>
              {profiles.map(p => (
                <Tr key={p.id}>
                  <Td>{p.id}</Td>
                  <Td><code>{JSON.stringify(p.config)}</code></Td>
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
      <Modal
        variant={ModalVariant.medium}
        title="Create Profile"
        isOpen={createOpen}
        onClose={() => setCreateOpen(false)}
        actions={[
          <Button key="save" form="profile-create-form" type="submit" variant="primary" isLoading={saving} isDisabled={saving}>Create</Button>,
          <Button key="cancel" variant="link" onClick={() => setCreateOpen(false)}>Cancel</Button>,
        ]}
      >
        <Form id="profile-create-form" onSubmit={handleCreate}>
          <FormGroup label="Profile ID" isRequired fieldId="profile-id">
            <TextInput id="profile-id" value={formId} onChange={(_e, v) => setFormId(v)} isRequired />
          </FormGroup>
          <FormGroup label="Config (JSON)" isRequired fieldId="profile-config">
            <TextArea id="profile-config" value={formConfig} onChange={(_e, v) => setFormConfig(v)} rows={10} isRequired />
          </FormGroup>
        </Form>
      </Modal>
      <Modal
        variant={ModalVariant.medium}
        title={`Edit Profile: ${editEntry?.id}`}
        isOpen={!!editEntry}
        onClose={() => setEditEntry(null)}
        actions={[
          <Button key="save" form="profile-edit-form" type="submit" variant="primary" isLoading={saving} isDisabled={saving}>Save</Button>,
          <Button key="cancel" variant="link" onClick={() => setEditEntry(null)}>Cancel</Button>,
        ]}
      >
        <Form id="profile-edit-form" onSubmit={handleUpdate}>
          <FormGroup label="Config (JSON)" isRequired fieldId="profile-edit-config">
            <TextArea id="profile-edit-config" value={formConfig} onChange={(_e, v) => setFormConfig(v)} rows={10} isRequired />
          </FormGroup>
        </Form>
      </Modal>
      <Modal
        variant={ModalVariant.small}
        title="Delete Profile"
        isOpen={!!deleteId}
        onClose={() => setDeleteId(null)}
        actions={[
          <Button key="confirm" variant="danger" onClick={handleDelete} isLoading={saving} isDisabled={saving}>Delete</Button>,
          <Button key="cancel" variant="link" onClick={() => setDeleteId(null)}>Cancel</Button>,
        ]}
      >
        <p>Delete profile <strong>{deleteId}</strong>?</p>
      </Modal>
    </>
  );
}
