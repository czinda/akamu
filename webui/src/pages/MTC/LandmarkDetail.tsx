import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  Button,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
} from '@patternfly/react-core';
import { getLandmarks, downloadLandmarkCert, getLandmarkCertDetails, type MtcLandmark } from '../../api/mtc';
import { CertTextBlock } from '../../components/CertTextBlock';
import { fmtTs, triggerBlobDownload } from '../../utils';
import { useAuth, hasRole } from '../../auth/AuthContext';

export default function MtcLandmarkDetail() {
  const { caId, seq } = useParams<{ caId: string; seq: string }>();
  const { role } = useAuth();
  const canDownload = hasRole(role, 'ca_operations');

  const [landmark, setLandmark] = useState<MtcLandmark | null>(null);
  const [certText, setCertText] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [certError, setCertError] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const seqNo = seq ? parseInt(seq, 10) : NaN;

  useEffect(() => {
    if (!caId || isNaN(seqNo)) return;

    const landmarkPromise = getLandmarks(caId).then((landmarks) => {
      const found = landmarks.find((l) => l.sequence_no === seqNo);
      if (found) setLandmark(found);
      else setError('Landmark not found');
    });

    const detailsPromise = getLandmarkCertDetails(seqNo, caId)
      .then((details) => setCertText(details.cert_text))
      .catch((e: unknown) => {
        setCertError(e instanceof Error ? e.message : 'Failed to load certificate details');
      });

    Promise.all([landmarkPromise, detailsPromise])
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [caId, seqNo]);

  async function handleDownload() {
    if (!caId || isNaN(seqNo)) return;
    setDownloadError(null);
    try {
      const blob = await downloadLandmarkCert(seqNo, caId);
      triggerBlobDownload(blob, `landmark-${seqNo}.der`);
    } catch (e: unknown) {
      setDownloadError(e instanceof Error ? e.message : 'Download failed');
    }
  }

  return (
    <>
      <PageSection>
        <Link to={`/mtc/${caId}`} style={{ fontSize: '0.875rem' }}>← Back to MTC: {caId}</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>Landmark #{seq}</Title>
      </PageSection>
      <PageSection>
        {loading && <Spinner />}
        {error && <Alert variant="danger" title={error} isInline />}
        {downloadError && <Alert variant="danger" title={downloadError} isInline style={{ marginTop: '0.5rem' }} />}
        {landmark && (
          <>
            <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: '640px' }}>
              <DescriptionListGroup>
                <DescriptionListTerm>Sequence No</DescriptionListTerm>
                <DescriptionListDescription>{landmark.sequence_no}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Tree Size</DescriptionListTerm>
                <DescriptionListDescription>{landmark.tree_size}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Created At</DescriptionListTerm>
                <DescriptionListDescription>{fmtTs(landmark.created_at)}</DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
            {canDownload && (
              <Button variant="secondary" size="sm" style={{ marginTop: '1rem' }} onClick={handleDownload}>
                Download Landmark Certificate
              </Button>
            )}
            {certError && <Alert variant="warning" title={certError} isInline style={{ marginTop: '1rem' }} />}
            <CertTextBlock certText={certText} />
          </>
        )}
      </PageSection>
    </>
  );
}
