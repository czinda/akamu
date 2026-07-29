import { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  PageSection,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  Button,
  Spinner,
  Alert,
  EmptyState,
  EmptyStateBody,
  TextInput,
  Pagination,
  Modal,
  ModalHeader,
  ModalBody,
  ModalFooter,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
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
import { fmtIso, auditSubjectPath } from '../../utils';
import { errorMessage } from '../../api/client';

const PAGE_SIZE = 50;

function AuditSubject({ eventType, subject }: { eventType: string; subject: string | null | undefined }) {
  if (!subject) return <>—</>;
  const path = auditSubjectPath(eventType, subject);
  if (path) return <Link to={path}>{subject}</Link>;
  return <>{subject}</>;
}

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [viewRow, setViewRow] = useState<AuditEntry | null>(null);
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
      setTotal(result.total);
    } catch (e: unknown) {
      setError(errorMessage(e, 'Failed to load audit log'));
    } finally {
      setLoading(false);
    }
  }, [page, typeFilter, outcomeFilter, fromFilter, untilFilter]);

  useEffect(() => { load(); }, [load]);

  return (
    <>
      <PageSection>
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
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {entries.map(e => (
                <Tr key={e.id}>
                  <Td>{fmtIso(e.occurred_at)}</Td>
                  <Td>{e.principal ?? '—'}</Td>
                  <Td>{e.event_type}</Td>
                  <Td><AuditSubject eventType={e.event_type} subject={e.subject} /></Td>
                  <Td>{e.outcome}</Td>
                  <Td><Button variant="plain" size="sm" onClick={() => setViewRow(e)}>View</Button></Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
        <Pagination itemCount={total} perPage={PAGE_SIZE} page={page} onSetPage={(_e, p) => setPage(p)} />
      </PageSection>
      <Modal variant="large" isOpen={!!viewRow} onClose={() => setViewRow(null)}>
        <ModalHeader title="Audit Event Details" />
        <ModalBody>
          <DescriptionList isHorizontal columnModifier={{ default: '1Col' }}>
            <DescriptionListGroup>
              <DescriptionListTerm>ID</DescriptionListTerm>
              <DescriptionListDescription>{viewRow?.id ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Occurred At</DescriptionListTerm>
              <DescriptionListDescription>{viewRow?.occurred_at != null ? fmtIso(viewRow.occurred_at) : '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Event Type</DescriptionListTerm>
              <DescriptionListDescription>{viewRow?.event_type ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Subject</DescriptionListTerm>
              <DescriptionListDescription>
                <AuditSubject eventType={viewRow?.event_type ?? ''} subject={viewRow?.subject} />
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Principal</DescriptionListTerm>
              <DescriptionListDescription>{viewRow?.principal ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Outcome</DescriptionListTerm>
              <DescriptionListDescription>{viewRow?.outcome ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Detail</DescriptionListTerm>
              <DescriptionListDescription>{viewRow?.detail ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
          </DescriptionList>
        </ModalBody>
        <ModalFooter>
          <Button variant="link" onClick={() => setViewRow(null)}>Close</Button>
        </ModalFooter>
      </Modal>
    </>
  );
}
