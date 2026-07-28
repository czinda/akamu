import { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  Button,
  Form,
  FormGroup,
  FormSection,
  TextInput,
  TextArea,
  FormSelect,
  FormSelectOption,
  ActionGroup,
  Card,
  CardBody,
  Switch,
  HelperText,
  HelperTextItem,
} from '@patternfly/react-core';
import { listScopes, getRule, createRule, updateRule } from '../../api/policy';
import { errorMessage } from '../../api/client';

function tryFormat(raw: string): string {
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}

interface Props {
  createMode?: boolean;
}

export default function PolicyEdit({ createMode }: Props) {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [scope, setScope] = useState('');
  const [name, setName] = useState('');
  const [ruleType, setRuleType] = useState<'allow' | 'deny'>('allow');
  const [enabled, setEnabled] = useState(true);
  const [ruleJson, setRuleJson] = useState('{\n  \n}');
  const [jsonError, setJsonError] = useState<string | null>(null);

  const [scopes, setScopes] = useState<string[]>([]);
  const [customScope, setCustomScope] = useState(false);
  const [loading, setLoading] = useState(!createMode);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);

  // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once at mount; scope is always '' here
  useEffect(() => {
    let ignore = false;
    listScopes()
      .then(s => {
        if (ignore) return;
        setScopes(s);
        if (s.length > 0 && !scope) setScope(s[0]);
        if (s.length === 0) setCustomScope(true);
      })
      .catch((e: unknown) => {
        if (ignore) return;
        setError(errorMessage(e, 'Failed to load scopes'));
      });
    return () => { ignore = true; };
  }, []);

  useEffect(() => {
    if (createMode || !id) { setLoading(false); return; }
    let ignore = false;
    getRule(id)
      .then(found => {
        if (ignore) return;
        setScope(found.scope);
        setName(found.name);
        setEnabled(found.enabled);
        if (found.corrupt) {
          setWarning('Rule JSON is corrupt — editing raw value');
          setRuleJson(JSON.stringify(found.rule_json, null, 2));
        } else {
          const parsed = found.rule_json;
          if (parsed.type === 'allow' || parsed.type === 'deny') {
            setRuleType(parsed.type as 'allow' | 'deny');
          } else {
            setWarning('Rule has no "type" field — defaulting to "allow"');
          }
          const { type: _, name: _n, ...rest } = parsed;
          setRuleJson(JSON.stringify(rest, null, 2));
        }
      })
      .catch((e: unknown) => {
        if (ignore) return;
        setError(errorMessage(e, 'Failed to load rule'));
      })
      .finally(() => { if (!ignore) setLoading(false); });
    return () => { ignore = true; };
  }, [id, createMode]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    let parsed: unknown;
    try {
      parsed = JSON.parse(ruleJson);
    } catch {
      setJsonError('Invalid JSON');
      return;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      setJsonError('Rule must be a JSON object');
      return;
    }
    setJsonError(null);

    const ruleObj = { ...(parsed as Record<string, unknown>), type: ruleType };

    setSaving(true);
    setError(null);
    try {
      if (createMode) {
        await createRule({ scope, name, rule: ruleObj, enabled });
      } else if (id) {
        await updateRule(id, { name, rule: ruleObj, enabled });
      } else {
        setError('Missing rule ID');
        return;
      }
      navigate('/policies');
    } catch (err: unknown) {
      setError(errorMessage(err, 'Save failed'));
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <PageSection><Spinner /></PageSection>;

  return (
    <>
      <PageSection>
        <Link to="/policies" style={{ fontSize: '0.875rem' }}>&larr; Back to Policies</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>
          {createMode ? 'Create Policy Rule' : 'Edit Policy Rule'}
        </Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        {warning && <Alert variant="warning" title={warning} isInline style={{ marginBottom: '1rem' }} />}
        <Form onSubmit={handleSubmit} style={{ maxWidth: '860px' }}>
          <Card>
            <CardBody>
              <FormSection title="Rule Identity">
                <FormGroup label="Scope" isRequired fieldId="pol-scope">
                  {createMode ? (
                    customScope ? (
                      <>
                        <TextInput
                          id="pol-scope"
                          value={scope}
                          onChange={(_e, v) => setScope(v)}
                          aria-label="Custom scope name"
                          placeholder="Enter scope name..."
                        />
                        {scopes.length > 0 && (
                          <Button variant="link" size="sm" onClick={() => { setCustomScope(false); if (!scopes.includes(scope) && scopes.length > 0) setScope(scopes[0]); }}>
                            Select existing scope
                          </Button>
                        )}
                      </>
                    ) : (
                      <>
                        <FormSelect id="pol-scope" value={scope} onChange={(_e, v) => setScope(v)} aria-label="Select scope">
                          {scopes.map(s => <FormSelectOption key={s} value={s} label={s} />)}
                        </FormSelect>
                        <Button variant="link" size="sm" onClick={() => setCustomScope(true)}>
                          Or type a new scope...
                        </Button>
                      </>
                    )
                  ) : (
                    <TextInput id="pol-scope-ro" value={scope} isDisabled aria-label="Scope (read-only)" />
                  )}
                </FormGroup>
                <FormGroup label="Name" isRequired fieldId="pol-name">
                  <TextInput id="pol-name" value={name} onChange={(_e, v) => setName(v)} isRequired placeholder="Unique rule name" />
                </FormGroup>
                <FormGroup label="Type" isRequired fieldId="pol-type">
                  <FormSelect id="pol-type" value={ruleType} onChange={(_e, v) => { if (v === 'allow' || v === 'deny') setRuleType(v); }} aria-label="Rule type">
                    <FormSelectOption value="allow" label="allow" />
                    <FormSelectOption value="deny" label="deny" />
                  </FormSelect>
                </FormGroup>
                <FormGroup label="Enabled" fieldId="pol-enabled">
                  <Switch id="pol-enabled" isChecked={enabled} onChange={(_e, v) => setEnabled(v)} label="Enabled" hasCheckIcon />
                </FormGroup>
              </FormSection>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <FormSection title="Rule Definition (JSON)">
                <FormGroup label="Rule JSON" isRequired fieldId="pol-rule-json">
                  <TextArea
                    id="pol-rule-json"
                    value={ruleJson}
                    onChange={(_e, v) => { setRuleJson(v); setJsonError(null); }}
                    onBlur={() => { if (ruleJson.trim()) setRuleJson(tryFormat(ruleJson)); }}
                    rows={12}
                    resizeOrientation="vertical"
                    validated={jsonError ? 'error' : 'default'}
                    aria-label="Rule JSON editor"
                    style={{ fontFamily: 'var(--pf-t--global--font--family--mono)', fontSize: '0.875rem' }}
                  />
                  <HelperText>
                    {jsonError
                      ? <HelperTextItem variant="error">{jsonError}</HelperTextItem>
                      : <HelperTextItem>
                          JSON object with dimension constraints. The &quot;type&quot; field is set by the dropdown above.
                          Example dimensions: profile, ca, account, account_group, identifier, key_type.
                        </HelperTextItem>}
                  </HelperText>
                </FormGroup>
              </FormSection>
            </CardBody>
          </Card>

          <ActionGroup>
            <Button type="submit" variant="primary" isLoading={saving}
              isDisabled={saving || !name.trim() || !ruleJson.trim() || (createMode === true && !scope.trim())}>
              {createMode ? 'Create' : 'Save'}
            </Button>
            <Button variant="link" onClick={() => navigate('/policies')} isDisabled={saving}>Cancel</Button>
          </ActionGroup>
        </Form>
      </PageSection>
    </>
  );
}
