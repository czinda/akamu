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
import { getCrossCert, CrossCertRow } from '../../api/crosscerts';
import { fmtTs } from '../../utils';
import { ObjLink } from '../../components/ObjLink';
import { CertTextBlock } from '../../components/CertTextBlock';

export default function CrossCertDetail() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<CrossCertRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    getCrossCert(id)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [id]);

  return (
    <>
      <PageSection>
        <Link to="/cross-certs" style={{ fontSize: '0.875rem' }}>← Back to Cross-Certs</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>Cross-Certificate: {id}</Title>
      </PageSection>
      <PageSection>
        {loading && <Spinner />}
        {error && <Alert variant="danger" title={error} isInline />}
        {data && (
          <>
            <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: '640px' }}>
              <DescriptionListGroup>
                <DescriptionListTerm>ID</DescriptionListTerm>
                <DescriptionListDescription>{data.id}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Issuer CA</DescriptionListTerm>
                <DescriptionListDescription><ObjLink type="ca" id={data.issuer_ca_id} /></DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Subject CA</DescriptionListTerm>
                <DescriptionListDescription><ObjLink type="ca" id={data.subject_ca_id} /></DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Subject DN</DescriptionListTerm>
                <DescriptionListDescription>{data.subject_dn ?? '—'}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Serial Number</DescriptionListTerm>
                <DescriptionListDescription>
                  <code style={{ fontSize: '0.875rem' }}>{data.serial_number ?? '—'}</code>
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Not Before</DescriptionListTerm>
                <DescriptionListDescription>{fmtTs(data.not_before)}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Not After</DescriptionListTerm>
                <DescriptionListDescription>{fmtTs(data.not_after)}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Created</DescriptionListTerm>
                <DescriptionListDescription>{fmtTs(data.created)}</DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
            <CertTextBlock
              pemLabel="Cross-Certificate PEM"
              pem={data.cross_cert_pem}
              certText={data.cert_text}
              downloadFilename={`cross-cert-${id}.pem`}
            />
          </>
        )}
      </PageSection>
    </>
  );
}
