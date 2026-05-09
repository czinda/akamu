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
import { getOrder, OrderRow } from '../../api/orders';
import { fmtTs, fmtIdentifiers } from '../../utils';
import { ObjLink } from '../../components/ObjLink';

export default function OrderDetail() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<OrderRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    getOrder(id)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [id]);

  return (
    <>
      <PageSection>
        <Link to="/orders" style={{ fontSize: '0.875rem' }}>← Back to Orders</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>Order: {id}</Title>
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
              <DescriptionListTerm>Status</DescriptionListTerm>
              <DescriptionListDescription>{data.status ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Identifiers</DescriptionListTerm>
              <DescriptionListDescription>
                <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>
                  {fmtIdentifiers(data.identifiers)}
                </pre>
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Profile</DescriptionListTerm>
              <DescriptionListDescription><ObjLink type="profile" id={data.profile} /></DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>CA</DescriptionListTerm>
              <DescriptionListDescription><ObjLink type="ca" id={data.ca_id} /></DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Certificate</DescriptionListTerm>
              <DescriptionListDescription><ObjLink type="cert" id={data.certificate_id} /></DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Created</DescriptionListTerm>
              <DescriptionListDescription>{fmtTs(data.created)}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Updated</DescriptionListTerm>
              <DescriptionListDescription>{fmtTs(data.updated)}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Expires</DescriptionListTerm>
              <DescriptionListDescription>{fmtTs(data.expires)}</DescriptionListDescription>
            </DescriptionListGroup>
          </DescriptionList>
        )}
      </PageSection>
    </>
  );
}
