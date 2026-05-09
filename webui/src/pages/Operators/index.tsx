import { useEffect, useState, useCallback } from 'react';
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
import { useNavigate } from 'react-router-dom';
import {
  listOperators,
  activateOperator,
  deactivateOperator,
  unlockOperator,
  OperatorRow,
} from '../../api/operators';
import { fmtIso } from '../../utils';

export default function Operators() {
  const navigate = useNavigate();
  const [operators, setOperators] = useState<OperatorRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listOperators();
      setOperators(result.operators);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load operators');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleAction(action: () => Promise<void>) {
    setSaving(true);
    try {
      await action();
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Action failed');
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Operators</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <Button variant="primary" onClick={() => navigate('/operators/new')}>Create Operator</Button>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
        {loading && <Spinner />}
        {!loading && operators.length === 0 && (
          <EmptyState><EmptyStateBody>No operators found.</EmptyStateBody></EmptyState>
        )}
        {!loading && operators.length > 0 && (
          <Table aria-label="Operators">
            <Thead>
              <Tr>
                <Th>Name</Th>
                <Th>Role</Th>
                <Th>Auth</Th>
                <Th>Status</Th>
                <Th>Last Seen</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {operators.map(op => (
                <Tr key={op.id}>
                  <Td>{op.name}</Td>
                  <Td>{op.role}{op.ca_id ? ` / ${op.ca_id}` : ''}</Td>
                  <Td style={{ fontSize: '0.8rem', color: '#666' }}>
                    {[op.gssapi_principal && 'GSSAPI', op.cert_fingerprint && 'mTLS'].filter(Boolean).join(', ') || '—'}
                  </Td>
                  <Td>
                    <Label color={op.active ? 'green' : 'red'}>{op.active ? 'active' : 'inactive'}</Label>
                    {op.locked && <>{' '}<Label color="orange">locked</Label></>}
                    {op.failed_attempts > 0 && !op.locked && <>{' '}<Label color="yellow">{op.failed_attempts} failed</Label></>}
                  </Td>
                  <Td>{fmtIso(op.last_seen_at)}</Td>
                  <Td>
                    <Button variant="plain" size="sm" onClick={() => navigate(`/operators/${op.id}`)}>View</Button>
                    {' '}
                    <Button variant="secondary" size="sm" onClick={() => navigate(`/operators/${op.id}/edit`)}>Edit</Button>
                    {' '}
                    {op.active
                      ? <Button variant="warning" size="sm" isDisabled={saving} onClick={() => handleAction(() => deactivateOperator(op.id))}>Deactivate</Button>
                      : <Button variant="secondary" size="sm" isDisabled={saving} onClick={() => handleAction(() => activateOperator(op.id))}>Activate</Button>
                    }
                    {op.locked && (
                      <>{' '}<Button variant="secondary" size="sm" isDisabled={saving} onClick={() => handleAction(() => unlockOperator(op.id))}>Unlock</Button></>
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
