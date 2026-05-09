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
import { getDelegation, DelegationRow } from '../../api/delegations';
import { fmtTs } from '../../utils';
import { ObjLink } from '../../components/ObjLink';

export default function DelegationDetail() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<DelegationRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    getDelegation(id)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [id]);

  return (
    <>
      <PageSection>
        <Link to="/delegations" style={{ fontSize: '0.875rem' }}>← Back to Delegations</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>Delegation: {id}</Title>
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
              <DescriptionListTerm>Account</DescriptionListTerm>
              <DescriptionListDescription><ObjLink type="account" id={data.account_id} /></DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>CSR Template</DescriptionListTerm>
              <DescriptionListDescription>
                <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>
                  {typeof data.csr_template === 'string' ? data.csr_template : JSON.stringify(data.csr_template, null, 2)}
                </pre>
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>CNAME Map</DescriptionListTerm>
              <DescriptionListDescription>
                {data.cname_map != null
                  ? <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>
                      {typeof data.cname_map === 'string' ? data.cname_map : JSON.stringify(data.cname_map, null, 2)}
                    </pre>
                  : '—'}
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
