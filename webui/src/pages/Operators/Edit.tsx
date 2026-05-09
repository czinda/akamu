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
  HelperText,
  HelperTextItem,
} from '@patternfly/react-core';
import {
  getOperator,
  createOperator,
  updateOperator,
  CreateOperatorOptions,
  UpdateOperatorOptions,
} from '../../api/operators';
import { listCas, CaInfo } from '../../api/cas';

const ROLES = ['administrator', 'ca_operations', 'ca_ra', 'auditor'];

const selectStyle: React.CSSProperties = {
  padding: '6px 8px',
  border: '1px solid #ccc',
  borderRadius: '4px',
  fontSize: 'inherit',
  width: '100%',
};

interface Props {
  createMode?: boolean;
}

export default function OperatorEdit({ createMode }: Props) {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [name, setName] = useState('');
  const [role, setRole] = useState('auditor');
  const [certFingerprint, setCertFingerprint] = useState('');
  const [gssapiPrincipal, setGssapiPrincipal] = useState('');
  const [caId, setCaId] = useState('');

  const [loading, setLoading] = useState(!createMode);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cas, setCas] = useState<CaInfo[]>([]);

  useEffect(() => {
    listCas().then(r => setCas(r.cas)).catch(() => {});
  }, []);

  useEffect(() => {
    if (createMode || !id) { setLoading(false); return; }
    getOperator(id)
      .then(op => {
        setName(op.name);
        setRole(op.role);
        setCertFingerprint(op.cert_fingerprint ?? '');
        setGssapiPrincipal(op.gssapi_principal ?? '');
        setCaId(op.ca_id ?? '');
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load operator'))
      .finally(() => setLoading(false));
  }, [id, createMode]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      if (createMode) {
        const opts: CreateOperatorOptions = { name, role };
        if (certFingerprint) opts.cert_fingerprint = certFingerprint;
        if (gssapiPrincipal) opts.gssapi_principal = gssapiPrincipal;
        if (caId) opts.ca_id = caId;
        const { id: newId } = await createOperator(opts);
        navigate(`/operators/${newId}`);
      } else {
        const opts: UpdateOperatorOptions = { name, role };
        if (certFingerprint !== '') opts.cert_fingerprint = certFingerprint;
        if (gssapiPrincipal !== '') opts.gssapi_principal = gssapiPrincipal;
        opts.ca_id = caId;
        await updateOperator(id!, opts);
        navigate(`/operators/${id}`);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Save failed');
      setSaving(false);
    }
  }

  const backPath = createMode ? '/operators' : `/operators/${id}`;
  const pageTitle = createMode ? 'Create Operator' : `Edit Operator: ${name || id}`;

  if (loading) return <PageSection><Spinner /></PageSection>;

  return (
    <>
      <PageSection>
        <Link to={backPath} style={{ fontSize: '0.875rem' }}>← {createMode ? 'Back to Operators' : `Back to ${name || id}`}</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>{pageTitle}</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Form onSubmit={handleSubmit} style={{ maxWidth: '640px' }}>
          <Card>
            <CardBody>
              <FormSection title="Identity">
                <FormGroup label="Name" isRequired fieldId="op-name">
                  <TextInput id="op-name" value={name} onChange={(_e, v) => setName(v)} isRequired />
                </FormGroup>
                <FormGroup label="Role" isRequired fieldId="op-role">
                  <select id="op-role" value={role} onChange={e => setRole(e.target.value)} style={selectStyle}>
                    {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                </FormGroup>
                {role === 'ca_ra' && (
                  <FormGroup label="CA Scope" isRequired fieldId="op-ca-id">
                    {cas.length > 0
                      ? (
                        <select id="op-ca-id" value={caId} onChange={e => setCaId(e.target.value)} style={selectStyle} required>
                          <option value="">— select a CA —</option>
                          {cas.map(ca => <option key={ca.id} value={ca.id}>{ca.id}</option>)}
                        </select>
                      )
                      : (
                        <TextInput id="op-ca-id" value={caId} onChange={(_e, v) => setCaId(v)} isRequired placeholder="CA ID" />
                      )}
                    <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>ca_ra operators must be scoped to a single CA.</p>
                  </FormGroup>
                )}
              </FormSection>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <FormSection title="Authentication">
                <HelperText style={{ marginBottom: '0.75rem' }}>
                  <HelperTextItem>At least one of certificate fingerprint or GSSAPI principal is required.</HelperTextItem>
                </HelperText>
                <FormGroup label="Certificate Fingerprint (SHA-256)" fieldId="op-cert-fp">
                  <TextInput id="op-cert-fp" value={certFingerprint} onChange={(_e, v) => setCertFingerprint(v)}
                    placeholder="aa:bb:cc:..." style={{ fontFamily: 'monospace' }} />
                  <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>Hex-encoded SHA-256 fingerprint of the client certificate used for mTLS auth.</p>
                </FormGroup>
                <FormGroup label="GSSAPI Principal" fieldId="op-gssapi">
                  <TextInput id="op-gssapi" value={gssapiPrincipal} onChange={(_e, v) => setGssapiPrincipal(v)}
                    placeholder="alice@EXAMPLE.COM" />
                  <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>Kerberos principal, e.g. alice@EXAMPLE.COM</p>
                </FormGroup>
              </FormSection>
            </CardBody>
          </Card>

          <ActionGroup>
            <Button type="submit" variant="primary" isLoading={saving}
              isDisabled={saving || !name.trim() || (role === 'ca_ra' && !caId)}>
              {createMode ? 'Create' : 'Save'}
            </Button>
            <Button variant="link" onClick={() => navigate(backPath)} isDisabled={saving}>Cancel</Button>
          </ActionGroup>
        </Form>
      </PageSection>
    </>
  );
}
