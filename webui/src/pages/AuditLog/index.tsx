import React, { useEffect, useState, useCallback } from 'react';
import {
  PageSection,
  PageSectionVariants,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  Spinner,
  Alert,
  EmptyState,
  EmptyStateBody,
  TextInput,
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
import { queryAudit, AuditEntry, AuditQueryParams } from '../../api/audit';

const PAGE_SIZE = 50;

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [typeFilter, setTypeFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [fromFilter, setFromFilter] = useState('');
  const [untilFilter, setUntilFilter] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: AuditQueryParams = { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE };
      if (typeFilter) params.type = typeFilter;
      if (outcomeFilter) params.outcome = outcomeFilter;
      if (fromFilter) params.from = fromFilter;
      if (untilFilter) params.until = untilFilter;
      const result = await queryAudit(params);
      setEntries(result.events);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load audit log');
    } finally {
      setLoading(false);
    }
  }, [page, typeFilter, outcomeFilter, fromFilter, untilFilter]);

  useEffect(() => { load(); }, [load]);

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Title headingLevel="h1">Audit Log</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <TextInput placeholder="Filter event type" value={typeFilter} onChange={(_e, v) => { setTypeFilter(v); setPage(1); }} />
            </ToolbarItem>
            <ToolbarItem>
              <select
                value={outcomeFilter}
                onChange={e => { setOutcomeFilter(e.target.value); setPage(1); }}
                style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px', fontSize: 'inherit' }}
              >
                <option value="">All outcomes</option>
                <option value="ok">ok</option>
                <option value="denied">denied</option>
                <option value="error">error</option>
              </select>
            </ToolbarItem>
            <ToolbarItem>
              <TextInput placeholder="From (ISO date)" value={fromFilter} onChange={(_e, v) => { setFromFilter(v); setPage(1); }} />
            </ToolbarItem>
            <ToolbarItem>
              <TextInput placeholder="Until (ISO date)" value={untilFilter} onChange={(_e, v) => { setUntilFilter(v); setPage(1); }} />
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
        {loading && <Spinner />}
        {!loading && entries.length === 0 && (
          <EmptyState><EmptyStateBody>No audit entries found.</EmptyStateBody></EmptyState>
        )}
        {!loading && entries.length > 0 && (
          <Table aria-label="Audit Log">
            <Thead>
              <Tr>
                <Th>Timestamp</Th>
                <Th>Principal</Th>
                <Th>Event Type</Th>
                <Th>Subject</Th>
                <Th>Outcome</Th>
                <Th>Detail</Th>
              </Tr>
            </Thead>
            <Tbody>
              {entries.map(e => (
                <Tr key={e.id}>
                  <Td>{e.occurred_at}</Td>
                  <Td>{e.principal ?? '—'}</Td>
                  <Td>{e.event_type}</Td>
                  <Td>{e.subject ?? '—'}</Td>
                  <Td>{e.outcome}</Td>
                  <Td>{e.detail ?? '—'}</Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
        <Pagination itemCount={entries.length} perPage={PAGE_SIZE} page={page} onSetPage={(_e, p) => setPage(p)} />
      </PageSection>
    </>
  );
}
