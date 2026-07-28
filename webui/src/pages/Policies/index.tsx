import { useEffect, useState, useCallback, useMemo } from 'react';
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
  Modal,
  ModalHeader,
  ModalBody,
  ModalFooter,
  Tabs,
  Tab,
  TabTitleText,
  Label,
} from '@patternfly/react-core';
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  ExpandableRowContent,
} from '@patternfly/react-table';
import { useNavigate } from 'react-router-dom';
import { listScopes, listRules, deleteRule, PolicyRule } from '../../api/policy';
import { fmtIso } from '../../utils';
import { useAuth, hasRole } from '../../auth/AuthContext';
import { errorMessage } from '../../api/client';

type RuleKind = 'allow' | 'deny' | 'unknown';

function ruleType(ruleJson: Record<string, unknown>): RuleKind {
  const t = ruleJson.type;
  if (t === 'allow' || t === 'deny') return t;
  return 'unknown';
}

function formatJson(raw: Record<string, unknown>): string {
  try { return JSON.stringify(raw, null, 2); } catch { return String(raw); }
}

export default function Policies() {
  const navigate = useNavigate();
  const { role } = useAuth();
  const canMutate = hasRole(role, 'administrator') || role === 'ca_operations';

  const [scopes, setScopes] = useState<string[]>([]);
  const [activeScope, setActiveScope] = useState<string>('');
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; name: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    let ignore = false;
    listScopes()
      .then(s => {
        if (ignore) return;
        setScopes(s);
        if (s.length > 0) {
          setActiveScope(s[0]);
        } else {
          setLoading(false);
        }
      })
      .catch((e: unknown) => {
        if (ignore) return;
        setError(errorMessage(e, 'Failed to load scopes'));
        setLoading(false);
      });
    return () => { ignore = true; };
  }, []);

  useEffect(() => {
    if (!activeScope) return;
    let ignore = false;
    setLoading(true);
    setError(null);
    setExpanded(new Set());
    listRules(activeScope)
      .then(r => { if (!ignore) setRules(r); })
      .catch((e: unknown) => { if (!ignore) setError(errorMessage(e, 'Failed to load rules')); })
      .finally(() => { if (!ignore) setLoading(false); });
    return () => { ignore = true; };
  }, [activeScope]);

  const loadRules = useCallback(async () => {
    if (!activeScope) return;
    setLoading(true);
    setError(null);
    setExpanded(new Set());
    try {
      setRules(await listRules(activeScope));
    } catch (e: unknown) {
      setError(errorMessage(e, 'Failed to load rules'));
    } finally {
      setLoading(false);
    }
  }, [activeScope]);

  const enrichedRules = useMemo(() =>
    rules.map(r => ({ ...r, parsedType: ruleType(r.rule_json) })),
    [rules]
  );

  async function handleDelete() {
    if (!deleteTarget) return;
    setSaving(true);
    try {
      await deleteRule(deleteTarget.id);
      setDeleteTarget(null);
      await loadRules();
    } catch (e: unknown) {
      setDeleteTarget(null);
      setError(errorMessage(e, 'Delete failed'));
    } finally {
      setSaving(false);
    }
  }

  function toggleExpand(id: string) {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Policies</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}

        {scopes.length > 0 && (
          <Tabs activeKey={activeScope} onSelect={(_e, key) => setActiveScope(key as string)} style={{ marginBottom: '1rem' }}>
            {scopes.map(s => (
              <Tab key={s} eventKey={s} title={<TabTitleText>{s}</TabTitleText>} />
            ))}
          </Tabs>
        )}

        <Toolbar>
          <ToolbarContent>
            {canMutate && (
              <ToolbarItem>
                <Button variant="primary" onClick={() => navigate('/policies/new')}>Create Rule</Button>
              </ToolbarItem>
            )}
          </ToolbarContent>
        </Toolbar>

        {loading && <Spinner />}
        {!loading && rules.length === 0 && scopes.length > 0 && (
          <EmptyState><EmptyStateBody>No rules in scope &quot;{activeScope}&quot;.</EmptyStateBody></EmptyState>
        )}
        {!loading && scopes.length === 0 && (
          <EmptyState><EmptyStateBody>No policy scopes found. Create a rule to get started.</EmptyStateBody></EmptyState>
        )}

        {!loading && rules.length > 0 && (
          <Table aria-label="Policy rules">
            <Thead>
              <Tr>
                <Th screenReaderText="Expand" />
                <Th>Name</Th>
                <Th>Type</Th>
                <Th>Enabled</Th>
                <Th>Created By</Th>
                <Th>Created At</Th>
                <Th>Updated At</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            {enrichedRules.map((r, rowIndex) => (
              <Tbody key={r.id} isExpanded={expanded.has(r.id)}>
                <Tr>
                  <Td
                    expand={{
                      rowIndex,
                      isExpanded: expanded.has(r.id),
                      onToggle: () => toggleExpand(r.id),
                    }}
                  />
                  <Td>{r.name}{r.corrupt && <>{' '}<Label color="red" isCompact>corrupt</Label></>}</Td>
                  <Td><Label color={r.parsedType === 'deny' ? 'red' : r.parsedType === 'allow' ? 'green' : 'orange'}>{r.parsedType}</Label></Td>
                  <Td><Label color={r.enabled ? 'blue' : 'grey'}>{r.enabled ? 'yes' : 'no'}</Label></Td>
                  <Td>{r.created_by ?? '—'}</Td>
                  <Td>{fmtIso(r.created_at)}</Td>
                  <Td>{fmtIso(r.updated_at)}</Td>
                  <Td>
                    {canMutate && <Button variant="secondary" size="sm" onClick={() => navigate(`/policies/${r.id}/edit`)}>Edit</Button>}
                    {canMutate && <>{' '}<Button variant="danger" size="sm" onClick={() => setDeleteTarget({ id: r.id, name: r.name })}>Delete</Button></>}
                  </Td>
                </Tr>
                <Tr isExpanded={expanded.has(r.id)}>
                  <Td />
                  <Td colSpan={7}>
                    <ExpandableRowContent>
                      <pre style={{ fontFamily: 'var(--pf-t--global--font--family--mono)', fontSize: '0.8rem', whiteSpace: 'pre-wrap', margin: 0 }}>{formatJson(r.rule_json)}</pre>
                    </ExpandableRowContent>
                  </Td>
                </Tr>
              </Tbody>
            ))}
          </Table>
        )}
      </PageSection>

      <Modal variant="small" isOpen={!!deleteTarget} onClose={() => setDeleteTarget(null)}>
        <ModalHeader title="Delete Policy Rule" />
        <ModalBody>
          {deleteTarget && (
            <p>Delete rule <strong>{deleteTarget.name}</strong>? This cannot be undone.</p>
          )}
        </ModalBody>
        <ModalFooter>
          <Button variant="danger" onClick={handleDelete} isLoading={saving} isDisabled={saving}>Delete</Button>
          <Button variant="link" onClick={() => setDeleteTarget(null)}>Cancel</Button>
        </ModalFooter>
      </Modal>
    </>
  );
}
