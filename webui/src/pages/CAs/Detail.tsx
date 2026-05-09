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
  Label,
} from '@patternfly/react-core';
import { getCa, CaInfo } from '../../api/cas';
import { CertTextBlock } from '../../components/CertTextBlock';

export default function CADetail() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<CaInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    getCa(id)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [id]);

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Link to="/cas" style={{ fontSize: '0.875rem' }}>← Back to CAs</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>CA: {id}</Title>
      </PageSection>
      <PageSection>
        {loading && <Spinner />}
        {error && <Alert variant="danger" title={error} isInline />}
        {data && (
          <>
            <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: '640px' }}>
              <DescriptionListGroup>
                <DescriptionListTerm>ID</DescriptionListTerm>
                <DescriptionListDescription>{data.id ?? '—'}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Key Type</DescriptionListTerm>
                <DescriptionListDescription>{data.key_type ?? '—'}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Hash Algorithm</DescriptionListTerm>
                <DescriptionListDescription>{data.hash_alg ?? '—'}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Validity Days</DescriptionListTerm>
                <DescriptionListDescription>{data.validity_days ?? '—'}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Default</DescriptionListTerm>
                <DescriptionListDescription>
                  {data.is_default ? <Label color="green">default</Label> : 'No'}
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
            <CertTextBlock
              pem={data.cert_pem}
              certText={data.cert_text}
              downloadFilename={`ca-${id}.pem`}
            />
          </>
        )}
      </PageSection>
    </>
  );
}
