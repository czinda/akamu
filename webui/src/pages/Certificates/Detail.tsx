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
  Label,
} from '@patternfly/react-core';
import { getCert, downloadCert, revokeCert, CertRow } from '../../api/certs';
import { fmtTs } from '../../utils';
import { ObjLink } from '../../components/ObjLink';
import { CertTextBlock } from '../../components/CertTextBlock';
import { useAuth, hasRole } from '../../auth/AuthContext';

export default function CertDetail() {
  const { id } = useParams<{ id: string }>();
  const { role } = useAuth();
  const canRevoke = hasRole(role, 'ca_operations');

  const [data, setData] = useState<CertRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState(false);

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

  async function handleRevoke() {
    if (!id || !data) return;
    setRevoking(true);
    try {
      await revokeCert(id, 'unspecified');
      setData({ ...data, status: 'revoked' });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Revoke failed');
    } finally {
      setRevoking(false);
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
            <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: '640px' }}>
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
                <DescriptionListDescription>
                  <code style={{ fontSize: '0.875rem' }}>{data.serial_number ?? '—'}</code>
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Subject DN</DescriptionListTerm>
                <DescriptionListDescription>{data.subject_dn ?? '—'}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Status</DescriptionListTerm>
                <DescriptionListDescription>
                  <Label color={data.status === 'valid' ? 'green' : data.status === 'revoked' ? 'red' : 'grey'}>
                    {data.status ?? '—'}
                  </Label>
                  {canRevoke && data.status === 'valid' && (
                    <Button variant="danger" size="sm" isDisabled={revoking}
                      style={{ marginLeft: '0.75rem' }}
                      onClick={handleRevoke}>
                      Revoke
                    </Button>
                  )}
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
              {data.revoked_at && (
                <DescriptionListGroup>
                  <DescriptionListTerm>Revoked At</DescriptionListTerm>
                  <DescriptionListDescription>{fmtTs(data.revoked_at)}</DescriptionListDescription>
                </DescriptionListGroup>
              )}
              {data.revocation_reason && (
                <DescriptionListGroup>
                  <DescriptionListTerm>Revocation Reason</DescriptionListTerm>
                  <DescriptionListDescription>{data.revocation_reason}</DescriptionListDescription>
                </DescriptionListGroup>
              )}
              {data.mtc_log_index != null && (
                <DescriptionListGroup>
                  <DescriptionListTerm>MTC Log Index</DescriptionListTerm>
                  <DescriptionListDescription>{data.mtc_log_index}</DescriptionListDescription>
                </DescriptionListGroup>
              )}
              {(data.suggested_window_start || data.suggested_window_end) && (
                <DescriptionListGroup>
                  <DescriptionListTerm>ARI Renewal Window</DescriptionListTerm>
                  <DescriptionListDescription>
                    {fmtTs(data.suggested_window_start)} – {fmtTs(data.suggested_window_end)}
                  </DescriptionListDescription>
                </DescriptionListGroup>
              )}
              {data.replaced_by && (
                <DescriptionListGroup>
                  <DescriptionListTerm>Replaced By Order</DescriptionListTerm>
                  <DescriptionListDescription><ObjLink type="order" id={data.replaced_by} /></DescriptionListDescription>
                </DescriptionListGroup>
              )}
            </DescriptionList>
            <CertTextBlock
              certText={data.cert_text}
              onDownload={handleDownload}
            />
          </>
        )}
      </PageSection>
    </>
  );
}
