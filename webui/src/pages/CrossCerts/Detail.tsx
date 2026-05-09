import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  PageSection,
  PageSectionVariants,
  Title,
  Spinner,
  Alert,
  Button,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
} from '@patternfly/react-core';
import { getCrossCert, downloadCrossCert, CrossCertRow } from '../../api/crosscerts';
import { fmtTs } from '../../utils';
import { ObjLink } from '../../components/ObjLink';

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

  async function handleDownload() {
    if (!id) return;
    try {
      const pem = await downloadCrossCert(id);
      const blob = new Blob([pem], { type: 'application/x-pem-file' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cross-cert-${id}.pem`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Download failed');
    }
  }

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Link to="/cross-certs" style={{ fontSize: '0.875rem' }}>← Back to Cross-Certs</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>Cross-Certificate: {id}</Title>
      </PageSection>
      <PageSection>
        {loading && <Spinner />}
        {error && <Alert variant="danger" title={error} isInline />}
        {data && (
          <>
            <DescriptionList isHorizontal columnModifier={{ default: '1Col' }}>
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
                <DescriptionListDescription>{data.serial_number ?? '—'}</DescriptionListDescription>
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
            <div style={{ marginTop: '1rem' }}>
              <Button variant="secondary" onClick={handleDownload}>Download PEM</Button>
            </div>
          </>
        )}
      </PageSection>
    </>
  );
}
