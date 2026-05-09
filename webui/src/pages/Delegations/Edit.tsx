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
  ActionGroup,
  Card,
  CardBody,
} from '@patternfly/react-core';
import {
  getDelegation,
  createDelegation,
  updateDelegation,
} from '../../api/delegations';
import { useAuth, hasRole } from '../../auth/AuthContext';

const taStyle: React.CSSProperties = {
  width: '100%',
  minHeight: '200px',
  fontFamily: 'monospace',
  fontSize: '0.875rem',
  padding: '8px',
  border: '1px solid #ccc',
  borderRadius: '4px',
  resize: 'vertical',
};

function tryFormat(raw: string): string {
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}

function toJsonString(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  return JSON.stringify(value, null, 2);
}

interface Props {
  createMode?: boolean;
}

export default function DelegationEdit({ createMode }: Props) {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { role } = useAuth();

  if (!hasRole(role, 'ca_operations')) {
    return (
      <PageSection>
        <Alert variant="danger" title="Access denied: creating or editing delegations requires ca_operations or administrator role." isInline />
      </PageSection>
    );
  }

  const [accountId, setAccountId] = useState('');
  const [csrTemplate, setCsrTemplate] = useState('{\n  \n}');
  const [cnameMap, setCnameMap] = useState('');
  const [csrError, setCsrError] = useState<string | null>(null);
  const [cnameError, setCnameError] = useState<string | null>(null);

  const [loading, setLoading] = useState(!createMode);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (createMode || !id) { setLoading(false); return; }
    getDelegation(id)
      .then(d => {
        setAccountId(d.account_id);
        setCsrTemplate(toJsonString(d.csr_template));
        setCnameMap(d.cname_map != null ? toJsonString(d.cname_map) : '');
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load delegation'))
      .finally(() => setLoading(false));
  }, [id, createMode]);

  function validateJson(value: string): unknown | null {
    if (!value.trim()) return null;
    try { return JSON.parse(value); } catch { return undefined; }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    const parsedCsr = validateJson(csrTemplate);
    if (parsedCsr === undefined) { setCsrError('Invalid JSON'); return; }
    setCsrError(null);

    const parsedCname = validateJson(cnameMap);
    if (parsedCname === undefined) { setCnameError('Invalid JSON'); return; }
    setCnameError(null);

    setSaving(true);
    setError(null);
    try {
      if (createMode) {
        const { id: newId } = await createDelegation({
          account_id: accountId,
          csr_template: parsedCsr,
          ...(parsedCname != null && { cname_map: parsedCname }),
        });
        navigate(`/delegations/${newId}`);
      } else {
        await updateDelegation(id!, {
          csr_template: parsedCsr,
          ...(parsedCname != null && { cname_map: parsedCname }),
        });
        navigate(`/delegations/${id}`);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Save failed');
      setSaving(false);
    }
  }

  const backPath = createMode ? '/delegations' : `/delegations/${id}`;
  const pageTitle = createMode ? 'Create Delegation' : `Edit Delegation: ${id}`;

  if (loading) return <PageSection><Spinner /></PageSection>;

  return (
    <>
      <PageSection>
        <Link to={backPath} style={{ fontSize: '0.875rem' }}>← {createMode ? 'Back to Delegations' : 'Back to delegation'}</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>{pageTitle}</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Form onSubmit={handleSubmit} style={{ maxWidth: '860px' }}>
          <Card>
            <CardBody>
              <FormSection title="Identity">
                {createMode
                  ? (
                    <FormGroup label="Account ID" isRequired fieldId="del-account-id">
                      <TextInput id="del-account-id" value={accountId} onChange={(_e, v) => setAccountId(v)} isRequired
                        placeholder="UUID of the ACME account" />
                    </FormGroup>
                  )
                  : (
                    <FormGroup label="Account ID" fieldId="del-account-id-ro">
                      <TextInput id="del-account-id-ro" value={accountId} isDisabled aria-label="Account ID (read-only)" />
                    </FormGroup>
                  )}
              </FormSection>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <FormSection title="CSR Template">
                <FormGroup label="CSR Template (JSON)" isRequired fieldId="del-csr">
                  <textarea
                    id="del-csr"
                    value={csrTemplate}
                    onChange={e => { setCsrTemplate(e.target.value); setCsrError(null); }}
                    onBlur={() => { if (csrTemplate.trim()) setCsrTemplate(tryFormat(csrTemplate)); }}
                    style={{ ...taStyle, borderColor: csrError ? '#c9190b' : '#ccc' }}
                    spellCheck={false}
                  />
                  {csrError
                    ? <p style={{ fontSize: '0.75rem', color: '#c9190b', marginTop: '0.25rem' }}>{csrError}</p>
                    : <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>JSON document specifying allowed/required CSR fields.</p>}
                </FormGroup>
              </FormSection>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <FormSection title="CNAME Map">
                <FormGroup label="CNAME Map (JSON, optional)" fieldId="del-cname">
                  <textarea
                    id="del-cname"
                    value={cnameMap}
                    onChange={e => { setCnameMap(e.target.value); setCnameError(null); }}
                    onBlur={() => { if (cnameMap.trim()) setCnameMap(tryFormat(cnameMap)); }}
                    style={{ ...taStyle, minHeight: '120px', borderColor: cnameError ? '#c9190b' : '#ccc' }}
                    spellCheck={false}
                    placeholder="{}"
                  />
                  {cnameError
                    ? <p style={{ fontSize: '0.75rem', color: '#c9190b', marginTop: '0.25rem' }}>{cnameError}</p>
                    : <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>{'Maps DNS names to CNAME targets. Example: {"_acme-challenge.example.com": "_acme.validation.example.com"}'}</p>}
                </FormGroup>
              </FormSection>
            </CardBody>
          </Card>

          <ActionGroup>
            <Button type="submit" variant="primary" isLoading={saving}
              isDisabled={saving || (createMode && !accountId.trim()) || !csrTemplate.trim()}>
              {createMode ? 'Create' : 'Save'}
            </Button>
            <Button variant="link" onClick={() => navigate(backPath)} isDisabled={saving}>Cancel</Button>
          </ActionGroup>
        </Form>
      </PageSection>
    </>
  );
}
