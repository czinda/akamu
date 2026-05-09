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
  Select,
  SelectOption,
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
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [actionFilter, setActionFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [outcomeOpen, setOutcomeOpen] = useState(false);
  const [fromFilter, setFromFilter] = useState('');
  const [toFilter, setToFilter] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: AuditQueryParams = { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE };
      if (actionFilter) params.action = actionFilter;
      if (outcomeFilter) params.outcome = outcomeFilter;
      if (fromFilter) params.from = fromFilter;
      if (toFilter) params.to = toFilter;
      const result = await queryAudit(params);
      setEntries(result.entries);
      setTotal(result.total ?? result.entries.length);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load audit log');
    } finally {
      setLoading(false);
    }
  }, [page, actionFilter, outcomeFilter, fromFilter, toFilter]);

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
              <TextInput placeholder="Filter action" value={actionFilter} onChange={(_e, v) => { setActionFilter(v); setPage(1); }} />
            </ToolbarItem>
            <ToolbarItem>
              <Select
                isOpen={outcomeOpen}
                onToggle={(_e, v) => setOutcomeOpen(v)}
                onSelect={(_e, v) => { setOutcomeFilter(v as string); setOutcomeOpen(false); setPage(1); }}
                selections={outcomeFilter || 'All outcomes'}
                placeholderText="All outcomes"
              >
                <SelectOption value="">All outcomes</SelectOption>
                <SelectOption value="ok">ok</SelectOption>
                <SelectOption value="denied">denied</SelectOption>
                <SelectOption value="error">error</SelectOption>
              </Select>
            </ToolbarItem>
            <ToolbarItem>
              <TextInput placeholder="From (ISO date)" value={fromFilter} onChange={(_e, v) => { setFromFilter(v); setPage(1); }} />
            </ToolbarItem>
            <ToolbarItem>
              <TextInput placeholder="To (ISO date)" value={toFilter} onChange={(_e, v) => { setToFilter(v); setPage(1); }} />
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
                <Th>Operator</Th>
                <Th>Action</Th>
                <Th>Target</Th>
                <Th>Outcome</Th>
                <Th>Detail</Th>
              </Tr>
            </Thead>
            <Tbody>
              {entries.map(e => (
                <Tr key={e.id}>
                  <Td>{e.ts}</Td>
                  <Td>{e.operator_name ?? e.operator_id ?? '—'}</Td>
                  <Td>{e.action}</Td>
                  <Td>{e.target_type ? `${e.target_type}/${e.target_id}` : '—'}</Td>
                  <Td>{e.outcome}</Td>
                  <Td>{e.detail ?? '—'}</Td>
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
