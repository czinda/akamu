import { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
  Button,
  Flex,
  FlexItem,
  Label,
} from '@patternfly/react-core';
import { getOperator, activateOperator, deactivateOperator, unlockOperator, OperatorRow } from '../../api/operators';
import { fmtIso } from '../../utils';
import { errorMessage } from '../../api/client';

export default function OperatorDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [data, setData] = useState<OperatorRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reload() {
    if (!id) return;
    getOperator(id)
      .then(setData)
      .catch((e: unknown) => setError(errorMessage(e, 'Failed to load')))
      .finally(() => setLoading(false));
  }

  useEffect(() => { reload(); }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  async function handleAction(action: () => Promise<void>) {
    setSaving(true);
    try {
      await action();
      reload();
    } catch (e: unknown) {
      setError(errorMessage(e, 'Action failed'));
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageSection>
        <Link to="/operators" style={{ fontSize: '0.875rem' }}>← Back to Operators</Link>
        <Flex style={{ marginTop: '0.5rem' }} alignItems={{ default: 'alignItemsCenter' }}>
          <FlexItem>
            <Title headingLevel="h1">Operator: {data?.name ?? id}</Title>
          </FlexItem>
          {data && (
            <>
              <FlexItem>
                <Button variant="secondary" onClick={() => navigate(`/operators/${id}/edit`)}>Edit</Button>
              </FlexItem>
              <FlexItem>
                {data.active
                  ? <Button variant="warning" isDisabled={saving} onClick={() => handleAction(() => deactivateOperator(id!))}>Deactivate</Button>
                  : <Button variant="secondary" isDisabled={saving} onClick={() => handleAction(() => activateOperator(id!))}>Activate</Button>
                }
              </FlexItem>
              {data.locked && (
                <FlexItem>
                  <Button variant="secondary" isDisabled={saving} onClick={() => handleAction(() => unlockOperator(id!))}>Unlock</Button>
                </FlexItem>
              )}
            </>
          )}
        </Flex>
      </PageSection>
      <PageSection>
        {loading && <Spinner />}
        {error && <Alert variant="danger" title={error} isInline />}
        {data && (
          <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: '640px' }}>
            <DescriptionListGroup>
              <DescriptionListTerm>ID</DescriptionListTerm>
              <DescriptionListDescription>{data.id}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Name</DescriptionListTerm>
              <DescriptionListDescription>{data.name}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Role</DescriptionListTerm>
              <DescriptionListDescription>{data.role}</DescriptionListDescription>
            </DescriptionListGroup>
            {data.ca_id && (
              <DescriptionListGroup>
                <DescriptionListTerm>CA Scope</DescriptionListTerm>
                <DescriptionListDescription>{data.ca_id}</DescriptionListDescription>
              </DescriptionListGroup>
            )}
            <DescriptionListGroup>
              <DescriptionListTerm>Status</DescriptionListTerm>
              <DescriptionListDescription>
                <Label color={data.active ? 'green' : 'red'}>{data.active ? 'active' : 'inactive'}</Label>
                {data.locked && <>{' '}<Label color="orange">locked</Label></>}
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Failed Attempts</DescriptionListTerm>
              <DescriptionListDescription>{data.failed_attempts}</DescriptionListDescription>
            </DescriptionListGroup>
            {data.locked_until && (
              <DescriptionListGroup>
                <DescriptionListTerm>Locked Until</DescriptionListTerm>
                <DescriptionListDescription>{fmtIso(data.locked_until)}</DescriptionListDescription>
              </DescriptionListGroup>
            )}
            <DescriptionListGroup>
              <DescriptionListTerm>GSSAPI Principal</DescriptionListTerm>
              <DescriptionListDescription>{data.gssapi_principal ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Certificate Fingerprint</DescriptionListTerm>
              <DescriptionListDescription>
                {data.cert_fingerprint
                  ? <code style={{ fontSize: '0.875rem' }}>{data.cert_fingerprint}</code>
                  : '—'}
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Created</DescriptionListTerm>
              <DescriptionListDescription>{fmtIso(data.created_at)}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Last Seen</DescriptionListTerm>
              <DescriptionListDescription>{fmtIso(data.last_seen_at)}</DescriptionListDescription>
            </DescriptionListGroup>
          </DescriptionList>
        )}
      </PageSection>
    </>
  );
}
