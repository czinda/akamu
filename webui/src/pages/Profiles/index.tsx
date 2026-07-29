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
import { listProfiles, deleteProfile, ProfileEntry } from '../../api/profiles';
import { useAuth, hasRole } from '../../auth/AuthContext';
import { errorMessage } from '../../api/client';

export default function Profiles() {
  const { role } = useAuth();
  const isAdmin = hasRole(role, 'administrator');
  const navigate = useNavigate();

  const [profiles, setProfiles] = useState<ProfileEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listProfiles();
      setProfiles(result.profiles);
    } catch (e: unknown) {
      setError(errorMessage(e, 'Failed to load profiles'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleDelete() {
    if (!deleteId) return;
    setSaving(true);
    try {
      await deleteProfile(deleteId);
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
        <Title headingLevel="h1">Profiles</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        {isAdmin && (
          <Toolbar>
            <ToolbarContent>
              <ToolbarItem>
                <Button variant="primary" onClick={() => navigate('/profiles/new')}>Create Profile</Button>
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
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {profiles.map(p => (
                <Tr key={p.id}>
                  <Td>{p.id}</Td>
                  <Td>{p.description || '—'}</Td>
                  <Td>{p.validity_days ?? '—'}</Td>
                  <Td>{p.hash_alg ?? '—'}</Td>
                  <Td>
                    <Button variant="plain" size="sm" onClick={() => navigate(`/profiles/${p.id}`)}>View</Button>
                    {isAdmin && (
                      <>
                        {' '}
                        <Button variant="secondary" size="sm" onClick={() => navigate(`/profiles/${p.id}/edit`)}>Edit</Button>
                        {' '}
                        <Button variant="danger" size="sm" onClick={() => setDeleteId(p.id)}>Delete</Button>
                      </>
                    )}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </PageSection>
      <Modal variant="small" isOpen={!!deleteId} onClose={() => setDeleteId(null)}>
        <ModalHeader title="Delete Profile" />
        <ModalBody>
          <p>Delete profile <strong>{deleteId}</strong>? This cannot be undone.</p>
        </ModalBody>
        <ModalFooter>
          <Button variant="danger" onClick={handleDelete} isLoading={saving} isDisabled={saving}>Delete</Button>
          <Button variant="link" onClick={() => setDeleteId(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>
    </>
  );
}
