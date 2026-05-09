import React, { useEffect, useState, useCallback } from 'react';
import {
  PageSection,
  PageSectionVariants,
  Title,
  Button,
  Spinner,
  Alert,
  EmptyState,
  EmptyStateBody,
  Pagination,
} from '@patternfly/react-core';
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
} from '@patternfly/react-table';
import { listCrossCerts, downloadCrossCert, CrossCertRow } from '../../api/crosscerts';

const PAGE_SIZE = 20;

export default function CrossCerts() {
  const [certs, setCerts] = useState<CrossCertRow[]>([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listCrossCerts({ limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE });
      setCerts(result.cross_certs);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load cross-certs');
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => { load(); }, [load]);

  async function handleDownload(id: string) {
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
        <Title headingLevel="h1">Cross-Certificates</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        {loading && <Spinner />}
        {!loading && certs.length === 0 && (
          <EmptyState><EmptyStateBody>No cross-certificates found.</EmptyStateBody></EmptyState>
        )}
        {!loading && certs.length > 0 && (
          <Table aria-label="Cross-Certificates">
            <Thead>
              <Tr>
                <Th>ID</Th>
                <Th>CA</Th>
                <Th>Subject CN</Th>
                <Th>Not Before</Th>
                <Th>Not After</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {certs.map(c => (
                <Tr key={c.id}>
                  <Td>{c.id}</Td>
                  <Td>{c.ca_id}</Td>
                  <Td>{c.subject_cn}</Td>
                  <Td>{c.not_before}</Td>
                  <Td>{c.not_after}</Td>
                  <Td>
                    <Button variant="secondary" size="sm" onClick={() => handleDownload(c.id)}>Download PEM</Button>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
        <Pagination itemCount={certs.length} perPage={PAGE_SIZE} page={page} onSetPage={(_e, p) => setPage(p)} />
      </PageSection>
    </>
  );
}
