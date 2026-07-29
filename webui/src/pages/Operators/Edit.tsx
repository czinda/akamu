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
  FormSelect,
  FormSelectOption,
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
import { errorMessage } from '../../api/client';

const ROLES = ['administrator', 'ca_operations', 'ca_ra', 'auditor'];

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
    let ignore = false;
    listCas()
      .then(r => { if (!ignore) setCas(r.cas); })
      .catch((e: unknown) => { if (!ignore) setError(errorMessage(e, 'Failed to load CAs')); });
    return () => { ignore = true; };
  }, []);

  useEffect(() => {
    if (createMode || !id) { setLoading(false); return; }
    let ignore = false;
    getOperator(id)
      .then(op => {
        if (ignore) return;
        setName(op.name);
        setRole(op.role);
        setCertFingerprint(op.cert_fingerprint ?? '');
        setGssapiPrincipal(op.gssapi_principal ?? '');
        setCaId(op.ca_id ?? '');
      })
      .catch((e: unknown) => { if (!ignore) setError(errorMessage(e, 'Failed to load operator')); })
      .finally(() => { if (!ignore) setLoading(false); });
    return () => { ignore = true; };
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
      } else if (id) {
        const opts: UpdateOperatorOptions = { name, role };
        if (certFingerprint !== '') opts.cert_fingerprint = certFingerprint;
        if (gssapiPrincipal !== '') opts.gssapi_principal = gssapiPrincipal;
        opts.ca_id = caId;
        await updateOperator(id, opts);
        navigate(`/operators/${id}`);
      } else {
        setError('Missing operator ID');
        setSaving(false);
        return;
      }
    } catch (err: unknown) {
      setError(errorMessage(err, 'Save failed'));
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
                  <FormSelect id="op-role" value={role} onChange={(_e, v) => setRole(v)} aria-label="Operator role">
                    {ROLES.map(r => <FormSelectOption key={r} value={r} label={r} />)}
                  </FormSelect>
                </FormGroup>
                <FormGroup label="CA Scope" isRequired={role === 'ca_ra'} fieldId="op-ca-id">
                    {cas.length > 0
                      ? (
                        <FormSelect id="op-ca-id" value={caId} onChange={(_e, v) => setCaId(v)} aria-label="CA scope" isRequired={role === 'ca_ra'}>
                          <FormSelectOption value="" label="— select a CA —" />
                          {cas.map(ca => <FormSelectOption key={ca.id} value={ca.id} label={ca.id} />)}
                        </FormSelect>
                      )
                      : (
                        <TextInput id="op-ca-id" value={caId} onChange={(_e, v) => setCaId(v)} isRequired={role === 'ca_ra'} placeholder="CA ID" />
                      )}
                    <HelperText>
                      <HelperTextItem>
                        {role === 'ca_ra' ? 'ca_ra operators must be scoped to a single CA.' : 'Optional — restricts this operator to a single CA.'}
                      </HelperTextItem>
                    </HelperText>
                  </FormGroup>
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
                    placeholder="aa:bb:cc:..." style={{ fontFamily: 'var(--pf-t--global--font--family--mono)' }} />
                  <HelperText>
                    <HelperTextItem>Hex-encoded SHA-256 fingerprint of the client certificate used for mTLS auth.</HelperTextItem>
                  </HelperText>
                </FormGroup>
                <FormGroup label="GSSAPI Principal" fieldId="op-gssapi">
                  <TextInput id="op-gssapi" value={gssapiPrincipal} onChange={(_e, v) => setGssapiPrincipal(v)}
                    placeholder="alice@EXAMPLE.COM" />
                  <HelperText>
                    <HelperTextItem>Kerberos principal, e.g. alice@EXAMPLE.COM</HelperTextItem>
                  </HelperText>
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
