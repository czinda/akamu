import { useEffect, useState } from 'react';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  EmptyState,
  EmptyStateBody,
  Label,
} from '@patternfly/react-core';
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
} from '@patternfly/react-table';
import { Link } from 'react-router-dom';
import { getStats, type ServerStats } from '../../api/stats';
import { fmtTs } from '../../utils';
import { errorMessage } from '../../api/client';

type MtcCaStats = ServerStats['mtc'][0];

export default function MtcOverview() {
  const [mtcStats, setMtcStats] = useState<MtcCaStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getStats()
      .then((stats) => setMtcStats(stats.mtc))
      .catch((e: unknown) => setError(errorMessage(e, 'Failed to load')))
      .finally(() => setLoading(false));
  }, []);

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Transparency Log</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        {loading && <Spinner />}
        {!loading && mtcStats.length === 0 && (
          <EmptyState><EmptyStateBody>No CAs with MTC configured.</EmptyStateBody></EmptyState>
        )}
        {!loading && mtcStats.length > 0 && (
          <Table aria-label="MTC Transparency Log">
            <Thead>
              <Tr>
                <Th>CA</Th>
                <Th>Status</Th>
                <Th>Tree Size</Th>
                <Th>Landmarks</Th>
                <Th>Last Checkpoint</Th>
                <Th>Last Landmark</Th>
                <Th>Cosigners</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {mtcStats.map((ca) => (
                <Tr key={ca.ca_id}>
                  <Td>{ca.ca_id}</Td>
                  <Td>
                    <Label color={ca.enabled ? 'green' : 'grey'}>
                      {ca.enabled ? 'enabled' : 'disabled'}
                    </Label>
                  </Td>
                  <Td>{ca.tree_size ?? '—'}</Td>
                  <Td>{ca.landmarks ?? '—'}</Td>
                  <Td>{fmtTs(ca.last_checkpoint_at)}</Td>
                  <Td>{fmtTs(ca.last_landmark_at)}</Td>
                  <Td>{ca.cosigner_count}</Td>
                  <Td>
                    {ca.enabled && (
                      <Link to={`/mtc/${ca.ca_id}`} style={{ fontSize: '0.875rem' }}>View</Link>
                    )}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </PageSection>
    </>
  );
}
