import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  PageSection,
  PageSectionVariants,
  Title,
  Spinner,
  Alert,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
} from '@patternfly/react-core';
import { getAccount, AccountRow } from '../../api/accounts';
import { fmtTs } from '../../utils';
import { ObjLink } from '../../components/ObjLink';

export default function AccountDetail() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<AccountRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    getAccount(id)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [id]);

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Link to="/accounts" style={{ fontSize: '0.875rem' }}>← Back to Accounts</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>Account: {id}</Title>
      </PageSection>
      <PageSection>
        {loading && <Spinner />}
        {error && <Alert variant="danger" title={error} isInline />}
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
