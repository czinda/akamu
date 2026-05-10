import { useEffect, useState, useCallback } from 'react';
import {
  PageSection,
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
import { useNavigate } from 'react-router-dom';
import { listCrossCerts, downloadCrossCert, CrossCertRow } from '../../api/crosscerts';
import { fmtTs } from '../../utils';
import { ObjLink } from '../../components/ObjLink';

const PAGE_SIZE = 20;

export default function CrossCerts() {
  const navigate = useNavigate();
  const [certs, setCerts] = useState<CrossCertRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listCrossCerts({ limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE });
      setCerts(result.cross_certs);
      setTotal(result.total);
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
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Download failed');
    }
  }

  return (
    <>
      <PageSection>
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
                <Th>Issuer CA</Th>
                <Th>Subject DN</Th>
                <Th>Not Before</Th>
                <Th>Not After</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {certs.map(c => (
                <Tr key={c.id}>
                  <Td>{c.id}</Td>
                  <Td><ObjLink type="ca" id={c.issuer_ca_id} /></Td>
                  <Td>{c.subject_dn}</Td>
                  <Td>{fmtTs(c.not_before)}</Td>
                  <Td>{fmtTs(c.not_after)}</Td>
                  <Td>
                    <Button variant="secondary" size="sm" onClick={() => handleDownload(c.id)}>Download PEM</Button>{' '}
                    <Button variant="plain" size="sm" onClick={() => navigate(`/cross-certs/${c.id}`)}>View</Button>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
        <Pagination itemCount={total} perPage={PAGE_SIZE} page={page} onSetPage={(_e, p) => setPage(p)} />
      </PageSection>
    </>
  );
}
