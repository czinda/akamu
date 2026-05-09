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
import { getCert, downloadCert, CertRow } from '../../api/certs';
import { fmtTs } from '../../utils';
import { ObjLink } from '../../components/ObjLink';

export default function CertDetail() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<CertRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    getCert(id)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [id]);

  async function handleDownload() {
    if (!id) return;
    try {
      const pem = await downloadCert(id);
      const blob = new Blob([pem], { type: 'application/x-pem-file' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cert-${id}.pem`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Download failed');
    }
  }

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Link to="/certs" style={{ fontSize: '0.875rem' }}>← Back to Certificates</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>Certificate: {id}</Title>
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
                <DescriptionListTerm>Order</DescriptionListTerm>
                <DescriptionListDescription><ObjLink type="order" id={data.order_id} /></DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Account</DescriptionListTerm>
                <DescriptionListDescription><ObjLink type="account" id={data.account_id} /></DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>CA</DescriptionListTerm>
                <DescriptionListDescription><ObjLink type="ca" id={data.ca_id} /></DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Serial Number</DescriptionListTerm>
                <DescriptionListDescription>{data.serial_number ?? '—'}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Subject DN</DescriptionListTerm>
                <DescriptionListDescription>{data.subject_dn ?? '—'}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Status</DescriptionListTerm>
                <DescriptionListDescription>{data.status ?? '—'}</DescriptionListDescription>
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
              <DescriptionListGroup>
                <DescriptionListTerm>Revoked At</DescriptionListTerm>
                <DescriptionListDescription>{fmtTs(data.revoked_at)}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Revocation Reason</DescriptionListTerm>
                <DescriptionListDescription>{data.revocation_reason ?? '—'}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>MTC Log Index</DescriptionListTerm>
                <DescriptionListDescription>{data.mtc_log_index ?? '—'}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>ARI Window Start</DescriptionListTerm>
                <DescriptionListDescription>{fmtTs(data.suggested_window_start)}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>ARI Window End</DescriptionListTerm>
                <DescriptionListDescription>{fmtTs(data.suggested_window_end)}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Replaced By Order</DescriptionListTerm>
                <DescriptionListDescription><ObjLink type="order" id={data.replaced_by} /></DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
            <div style={{ marginTop: '1rem' }}>
              <Button variant="secondary" onClick={handleDownload}>Download PEM</Button>
            </div>
            {data.cert_text && (
              <div style={{ marginTop: '1.5rem' }}>
                <Title headingLevel="h2" size="md" style={{ marginBottom: '0.5rem' }}>
                  Certificate Details
                </Title>
                <pre style={{
                  fontFamily: 'monospace',
                  fontSize: '0.8rem',
                  background: 'var(--pf-v6-global--BackgroundColor--200, #f5f5f5)',
                  border: '1px solid var(--pf-v6-global--BorderColor--100, #d2d2d2)',
                  borderRadius: '4px',
                  padding: '1rem',
                  overflowX: 'auto',
                  whiteSpace: 'pre',
                }}>
                  {data.cert_text}
                </pre>
              </div>
            )}
          </>
        )}
      </PageSection>
    </>
  );
}
