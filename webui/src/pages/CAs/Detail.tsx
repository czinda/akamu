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
  Label,
} from '@patternfly/react-core';
import { getCa, CaInfo } from '../../api/cas';
import { getStats, type ServerStats } from '../../api/stats';
import { fmtTs } from '../../utils';
import { CertTextBlock } from '../../components/CertTextBlock';

export default function CADetail() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<CaInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mtcStats, setMtcStats] = useState<ServerStats['mtc'][0] | null>(null);
  const [mtcError, setMtcError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    getCa(id)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
    getStats()
      .then((stats) => {
        const ca = stats.mtc.find((m) => m.ca_id === id);
        if (ca) setMtcStats(ca);
      })
      .catch((e: unknown) => setMtcError(e instanceof Error ? e.message : 'Failed to load MTC stats'));
  }, [id]);

  return (
    <>
      <PageSection>
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

            <Title headingLevel="h2" size="md" style={{ marginTop: '1.5rem', marginBottom: '0.5rem' }}>
              MTC Transparency Log
            </Title>
            {mtcError && <Alert variant="warning" title={mtcError} isInline style={{ marginBottom: '0.5rem' }} />}
            {mtcStats ? (
              mtcStats.enabled ? (
                <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: '640px', marginBottom: '1rem' }}>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Status</DescriptionListTerm>
                    <DescriptionListDescription>
                      <Label color="green">enabled</Label>
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Tree Size</DescriptionListTerm>
                    <DescriptionListDescription>{mtcStats.tree_size ?? '—'}</DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Landmarks</DescriptionListTerm>
                    <DescriptionListDescription>{mtcStats.landmarks ?? '—'}</DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Last Checkpoint</DescriptionListTerm>
                    <DescriptionListDescription>{fmtTs(mtcStats.last_checkpoint_at)}</DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Details</DescriptionListTerm>
                    <DescriptionListDescription>
                      <Link to={`/mtc/${id}`}>View full MTC details →</Link>
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                </DescriptionList>
              ) : (
                <Label color="grey">MTC not enabled</Label>
              )
            ) : (
              <Label color="grey">MTC not configured</Label>
            )}

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
