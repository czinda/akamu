import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
} from '@patternfly/react-core';
import { getEab, EabKeyRow } from '../../api/eab';
import { fmtTs } from '../../utils';
import { ObjLink } from '../../components/ObjLink';

export default function EabKeyDetail() {
  const { kid } = useParams<{ kid: string }>();
  const [data, setData] = useState<EabKeyRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!kid) return;
    getEab(kid)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [kid]);

  return (
    <>
      <PageSection>
        <Link to="/eab" style={{ fontSize: '0.875rem' }}>← Back to EAB Keys</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>EAB Key: {kid}</Title>
      </PageSection>
      <PageSection>
        {loading && <Spinner />}
        {error && <Alert variant="danger" title={error} isInline />}
        {data && (
          <DescriptionList isHorizontal columnModifier={{ default: '1Col' }}>
            <DescriptionListGroup>
              <DescriptionListTerm>KID</DescriptionListTerm>
              <DescriptionListDescription>{data.kid}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Algorithm</DescriptionListTerm>
              <DescriptionListDescription>{data.alg ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Bound Principal</DescriptionListTerm>
              <DescriptionListDescription>{data.bound_principal ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Created By Operator</DescriptionListTerm>
              <DescriptionListDescription>
                <ObjLink type="operator" id={data.created_by_operator_id} />
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
              <DescriptionListTerm>Used At</DescriptionListTerm>
              <DescriptionListDescription>{fmtTs(data.used_at)}</DescriptionListDescription>
            </DescriptionListGroup>
          </DescriptionList>
        )}
      </PageSection>
    </>
  );
}
