import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  Button,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
  TextInput,
} from '@patternfly/react-core';
import { getAccount, setGrants, clearGrants, AccountRow } from '../../api/accounts';
import { fmtTs } from '../../utils';
import { ObjLink } from '../../components/ObjLink';
import { useAuth, hasRole } from '../../auth/AuthContext';

export default function AccountDetail() {
  const { id } = useParams<{ id: string }>();
  const { role } = useAuth();
  const canEdit = hasRole(role, 'ca_operations');

  const [data, setData] = useState<AccountRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [editingGrants, setEditingGrants] = useState(false);
  const [draftGrants, setDraftGrants] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!id) return;
    getAccount(id)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [id]);

  function startEdit() {
    if (!data) return;
    setDraftGrants(data.profile_grants ? data.profile_grants.join(', ') : '');
    setEditingGrants(true);
  }

  async function handleSave() {
    if (!id) return;
    setSaving(true);
    try {
      const grants = draftGrants.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
      await setGrants(id, grants);
      const updated = await getAccount(id);
      setData(updated);
      setEditingGrants(false);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to save grants');
    } finally {
      setSaving(false);
    }
  }

  async function handleClear() {
    if (!id) return;
    setSaving(true);
    try {
      await clearGrants(id);
      const updated = await getAccount(id);
      setData(updated);
      setEditingGrants(false);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to clear grants');
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageSection>
        <Link to="/accounts" style={{ fontSize: '0.875rem' }}>← Back to Accounts</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>Account: {id}</Title>
      </PageSection>
      <PageSection>
        {loading && <Spinner />}
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        {data && (
          <DescriptionList isHorizontal columnModifier={{ default: '1Col' }}>
            <DescriptionListGroup>
              <DescriptionListTerm>ID</DescriptionListTerm>
              <DescriptionListDescription>{data.id}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Status</DescriptionListTerm>
              <DescriptionListDescription>{data.status ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>CA</DescriptionListTerm>
              <DescriptionListDescription><ObjLink type="ca" id={data.ca_id} /></DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>JWK Thumbprint</DescriptionListTerm>
              <DescriptionListDescription>{data.jwk_thumbprint ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Contact</DescriptionListTerm>
              <DescriptionListDescription>
                <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{data.contact ?? '—'}</pre>
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Profile Grants</DescriptionListTerm>
              <DescriptionListDescription>
                {editingGrants ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxWidth: '420px' }}>
                    <TextInput
                      value={draftGrants}
                      onChange={(_e, v) => setDraftGrants(v)}
                      placeholder="profile-a, profile-b  (empty = unrestricted)"
                      aria-label="Profile grants"
                    />
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <Button variant="primary" size="sm" onClick={handleSave} isLoading={saving} isDisabled={saving}>Save</Button>
                      <Button variant="danger" size="sm" onClick={handleClear} isDisabled={saving}>Clear (unrestrict)</Button>
                      <Button variant="link" size="sm" onClick={() => setEditingGrants(false)} isDisabled={saving}>Cancel</Button>
                    </div>
                  </div>
                ) : (
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <span>
                      {data.profile_grants == null
                        ? '— (unrestricted)'
                        : data.profile_grants.length === 0
                          ? '— (none)'
                          : data.profile_grants.map((g, i) => (
                              <span key={g}>
                                {i > 0 && ', '}
                                <ObjLink type="profile" id={g} />
                              </span>
                            ))}
                    </span>
                    {canEdit && (
                      <Button variant="plain" size="sm" onClick={startEdit} style={{ padding: 0 }}>Edit</Button>
                    )}
                  </span>
                )}
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Created</DescriptionListTerm>
              <DescriptionListDescription>{fmtTs(data.created)}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Updated</DescriptionListTerm>
              <DescriptionListDescription>{fmtTs(data.updated)}</DescriptionListDescription>
            </DescriptionListGroup>
          </DescriptionList>
        )}
      </PageSection>
    </>
  );
}
