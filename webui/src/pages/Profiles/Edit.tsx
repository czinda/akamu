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
  Checkbox,
  Radio,
  ActionGroup,
  Card,
  CardBody,
} from '@patternfly/react-core';
import { getProfile, updateProfile, createProfile, ProfilePayload } from '../../api/profiles';
import { listCas, CaInfo } from '../../api/cas';
import { errorMessage } from '../../api/client';

/* ── Key Usage bit positions (from synta-certificate / RFC 5280) ── */
const KEY_USAGE_BITS: { bit: number; label: string }[] = [
  { bit: 0, label: 'digitalSignature' },
  { bit: 1, label: 'nonRepudiation' },
  { bit: 2, label: 'keyEncipherment' },
  { bit: 3, label: 'dataEncipherment' },
  { bit: 4, label: 'keyAgreement' },
  { bit: 5, label: 'keyCertSign' },
  { bit: 6, label: 'cRLSign' },
  { bit: 7, label: 'encipherOnly' },
  { bit: 8, label: 'decipherOnly' },
];

const HASH_ALGS = ['sha256', 'sha384', 'sha512'];
const COMMON_EKUS = ['server_auth', 'client_auth', 'code_signing', 'email_protection', 'time_stamping', 'ocsp_signing'];
const COMMON_KEY_TYPES = [
  'ec:P-256', 'ec:P-384', 'ec:P-521', 'ed25519',
  'rsa:2048', 'rsa:3072', 'rsa:4096',
  'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87',
];
const PQC_KEY_TYPE_PREFIX = 'ml-dsa-';

function emptyPayload(): ProfilePayload {
  return {
    description: '',
    validity_days: 90,
    hash_alg: 'sha256',
    key_usage_bits: 0,
    extended_key_usages: [],
    crl_url: null,
    ocsp_url: null,
    allowed_key_types: [],
    certificate_policies: [],
    issue_as_mtc: false,
    allowed_identifier_patterns: [],
    identifier_match_all: true,
    auth_hook: null,
    auth_hook_timeout_secs: 30,
    require_account_grant: false,
    ca_ids: [],
  };
}

/* ── Simple editable string-list sub-component ─────────────────── */
function StringList({
  label, values, suggestions, onChange, placeholder,
}: {
  label: string;
  values: string[];
  suggestions?: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
}) {
  const [input, setInput] = useState('');

  function add() {
    const v = input.trim();
    if (v && !values.includes(v)) onChange([...values, v]);
    setInput('');
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
        <TextInput
          aria-label={label}
          value={input}
          onChange={(_e, v) => setInput(v)}
          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add(); } }}
          placeholder={placeholder}
          style={{ flex: 1 }}
        />
        <Button variant="secondary" size="sm" onClick={add} isDisabled={!input.trim()}>Add</Button>
      </div>
      {suggestions && suggestions.filter(s => !values.includes(s)).length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginBottom: '0.5rem' }}>
          {suggestions.filter(s => !values.includes(s)).map(s => (
            <Button key={s} variant="plain" size="sm"
              style={{ padding: '2px 8px', border: '1px solid #ccc', borderRadius: '3px', fontSize: '0.8rem' }}
              onClick={() => onChange([...values, s])}>
              + {s}
            </Button>
          ))}
        </div>
      )}
      {values.length > 0 && (
        <ul style={{ margin: 0, paddingLeft: 0, listStyle: 'none', display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
          {values.map(v => (
            <li key={v} style={{ display: 'flex', alignItems: 'center', gap: '4px',
              background: '#f0f0f0', padding: '2px 8px', borderRadius: '3px', fontSize: '0.875rem' }}>
              {v}
              <button onClick={() => onChange(values.filter(x => x !== v))}
                style={{ border: 'none', background: 'none', cursor: 'pointer', padding: '0 2px', color: '#666' }}>×</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/* ── Certificate policies sub-component ─────────────────────────── */
function PolicyList({
  policies, onChange,
}: {
  policies: [string, string | null][];
  onChange: (p: [string, string | null][]) => void;
}) {
  const [oid, setOid] = useState('');
  const [cps, setCps] = useState('');

  function add() {
    const o = oid.trim();
    if (!o) return;
    onChange([...policies, [o, cps.trim() || null]]);
    setOid(''); setCps('');
  }

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: '0.5rem', marginBottom: '0.5rem' }}>
        <TextInput aria-label="Policy OID" value={oid} onChange={(_e, v) => setOid(v)} placeholder="OID (e.g. 2.5.29.32.0)" />
        <TextInput aria-label="CPS URI" value={cps} onChange={(_e, v) => setCps(v)} placeholder="CPS URI (optional)" />
        <Button variant="secondary" size="sm" onClick={add} isDisabled={!oid.trim()}>Add</Button>
      </div>
      {policies.length > 0 && (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', padding: '4px 8px', borderBottom: '1px solid #ddd' }}>OID</th>
              <th style={{ textAlign: 'left', padding: '4px 8px', borderBottom: '1px solid #ddd' }}>CPS URI</th>
              <th style={{ padding: '4px 8px', borderBottom: '1px solid #ddd' }}></th>
            </tr>
          </thead>
          <tbody>
            {policies.map(([o, c], i) => (
              <tr key={i}>
                <td style={{ padding: '4px 8px' }}>{o}</td>
                <td style={{ padding: '4px 8px' }}>{c ?? '—'}</td>
                <td style={{ padding: '4px 8px' }}>
                  <button onClick={() => onChange(policies.filter((_, j) => j !== i))}
                    style={{ border: 'none', background: 'none', cursor: 'pointer', color: '#c9190b' }}>Remove</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

interface Props {
  createMode?: boolean;
}

export default function ProfileEdit({ createMode }: Props) {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [form, setForm] = useState<ProfilePayload>(emptyPayload());
  const [formId, setFormId] = useState('');
  const [loading, setLoading] = useState(!createMode);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cas, setCas] = useState<CaInfo[]>([]);

  useEffect(() => {
    listCas().then(r => setCas(r.cas)).catch(() => {});
  }, []);

  useEffect(() => {
    if (createMode || !id) { setLoading(false); return; }
    getProfile(id)
      .then(p => {
        setForm({
          description: p.description ?? '',
          validity_days: p.validity_days ?? 90,
          hash_alg: p.hash_alg ?? 'sha256',
          key_usage_bits: p.key_usage_bits ?? 0,
          extended_key_usages: p.extended_key_usages ?? [],
          crl_url: p.crl_url ?? null,
          ocsp_url: p.ocsp_url ?? null,
          allowed_key_types: p.allowed_key_types ?? [],
          certificate_policies: p.certificate_policies ?? [],
          issue_as_mtc: p.issue_as_mtc ?? false,
          allowed_identifier_patterns: p.allowed_identifier_patterns ?? [],
          identifier_match_all: p.identifier_match_all ?? true,
          auth_hook: p.auth_hook ?? null,
          auth_hook_timeout_secs: p.auth_hook_timeout_secs ?? 30,
          require_account_grant: p.require_account_grant ?? false,
          ca_ids: p.ca_ids ?? [],
        });
      })
      .catch((e: unknown) => setError(errorMessage(e, 'Failed to load profile')))
      .finally(() => setLoading(false));
  }, [id, createMode]);

  function set<K extends keyof ProfilePayload>(key: K, value: ProfilePayload[K]) {
    setForm(f => ({ ...f, [key]: value }));
  }

  function toggleKeyUsageBit(bit: number, checked: boolean) {
    const mask = 1 << bit;
    set('key_usage_bits', checked ? (form.key_usage_bits | mask) : (form.key_usage_bits & ~mask));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      if (createMode) {
        await createProfile(formId.trim(), form);
        navigate(`/profiles/${formId.trim()}`);
      } else {
        await updateProfile(id!, form);
        navigate(`/profiles/${id}`);
      }
    } catch (err: unknown) {
      setError(errorMessage(err, 'Save failed'));
      setSaving(false);
    }
  }

  if (loading) return <PageSection><Spinner /></PageSection>;

  const pageTitle = createMode ? 'Create Profile' : `Edit Profile: ${id}`;
  const backPath = createMode ? '/profiles' : `/profiles/${id}`;
  const onlyPqcTypes = form.allowed_key_types.length > 0
    && form.allowed_key_types.every(t => t.startsWith(PQC_KEY_TYPE_PREFIX));

  return (
    <>
      <PageSection>
        <Link to={backPath} style={{ fontSize: '0.875rem' }}>← {createMode ? 'Back to Profiles' : `Back to ${id}`}</Link>
        <Title headingLevel="h1" style={{ marginTop: '0.5rem' }}>{pageTitle}</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Form onSubmit={handleSubmit} style={{ maxWidth: '860px' }}>

          {/* ── Identity ─────────────────────────────────────────── */}
          <Card>
            <CardBody>
              <FormSection title="Identity">
                {createMode && (
                  <FormGroup label="Profile ID" isRequired fieldId="pf-id">
                    <TextInput id="pf-id" value={formId} onChange={(_e, v) => setFormId(v)} isRequired
                      placeholder="e.g. tls-server" />
                  </FormGroup>
                )}
                <FormGroup label="Description" fieldId="pf-desc">
                  <TextInput id="pf-desc" value={form.description} onChange={(_e, v) => set('description', v)} />
                </FormGroup>
              </FormSection>
            </CardBody>
          </Card>

          {/* ── Certificate parameters ───────────────────────────── */}
          <Card>
            <CardBody>
              <FormSection title="Certificate Parameters">
                <FormGroup label="Validity (days)" isRequired fieldId="pf-validity">
                  <TextInput id="pf-validity" type="number" value={String(form.validity_days)}
                    onChange={(_e, v) => set('validity_days', parseInt(v, 10) || 90)} isRequired style={{ maxWidth: '12rem' }} />
                </FormGroup>
                <FormGroup label="Hash Algorithm" isRequired fieldId="pf-hash">
                  <select id="pf-hash" value={form.hash_alg} onChange={e => set('hash_alg', e.target.value)}
                    style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px', fontSize: 'inherit', width: '12rem',
                      opacity: onlyPqcTypes ? 0.5 : 1 }}>
                    {HASH_ALGS.map(h => <option key={h} value={h}>{h}</option>)}
                  </select>
                  {onlyPqcTypes && <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>Not used for ML-DSA key types — post-quantum signatures embed the hash internally. This value is stored but ignored when signing with ML-DSA keys.</p>}
                </FormGroup>
                <FormGroup label="Key Usage" fieldId="pf-ku">
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.25rem 1rem' }}>
                    {KEY_USAGE_BITS.map(({ bit, label }) => (
                      <Checkbox key={bit} id={`ku-${bit}`} label={label}
                        isChecked={!!(form.key_usage_bits & (1 << bit))}
                        onChange={(_e, checked) => toggleKeyUsageBit(bit, checked)} />
                    ))}
                  </div>
                  <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>Zero bits selected = KeyUsage extension omitted from issued certificates.</p>
                </FormGroup>
                <FormGroup label="Extended Key Usages" fieldId="pf-eku">
                  <StringList label="Extended Key Usages" values={form.extended_key_usages}
                    suggestions={COMMON_EKUS} placeholder="server_auth or 1.3.6.1.5.5.7.3.1"
                    onChange={v => set('extended_key_usages', v)} />
                  <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>{'Short names (e.g. "server_auth") or raw OIDs.'}</p>
                </FormGroup>
                <FormGroup label="Allowed Key Types" fieldId="pf-kt">
                  <StringList label="Allowed Key Types" values={form.allowed_key_types}
                    suggestions={COMMON_KEY_TYPES} placeholder="ec:P-256"
                    onChange={v => set('allowed_key_types', v)} />
                  <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>{'Empty = any key type accepted. Format: "ec:P-256", "rsa:2048", "ed25519", "ml-dsa-44", etc. ML-DSA requires allow_post_quantum = true in server config.'}</p>
                </FormGroup>
              </FormSection>
            </CardBody>
          </Card>

          {/* ── Extensions ───────────────────────────────────────── */}
          <Card>
            <CardBody>
              <FormSection title="Extensions">
                <FormGroup label="CRL Distribution Point URL" fieldId="pf-crl">
                  <TextInput id="pf-crl" value={form.crl_url ?? ''}
                    onChange={(_e, v) => set('crl_url', v || null)}
                    placeholder="http://crl.example.com/ca.crl" style={{ maxWidth: '480px' }} />
                  <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>Empty = CRLDistributionPoints extension omitted.</p>
                </FormGroup>
                <FormGroup label="OCSP Responder URL" fieldId="pf-ocsp">
                  <TextInput id="pf-ocsp" value={form.ocsp_url ?? ''}
                    onChange={(_e, v) => set('ocsp_url', v || null)}
                    placeholder="http://ocsp.example.com" style={{ maxWidth: '480px' }} />
                  <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>Empty = AuthorityInfoAccess extension omitted.</p>
                </FormGroup>
                <FormGroup label="Certificate Policies" fieldId="pf-cp">
                  <PolicyList policies={form.certificate_policies}
                    onChange={p => set('certificate_policies', p)} />
                </FormGroup>
              </FormSection>
            </CardBody>
          </Card>

          {/* ── Identifier constraints ───────────────────────────── */}
          <Card>
            <CardBody>
              <FormSection title="Identifier Constraints">
                <FormGroup label="Allowed Identifier Patterns" fieldId="pf-ident">
                  <StringList label="Identifier patterns" values={form.allowed_identifier_patterns}
                    placeholder="dns:.*\.example\.com"
                    onChange={v => set('allowed_identifier_patterns', v)} />
                  <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>{'Regex patterns matched against "type:value" (e.g. "dns:.*\\.example\\.com"). Empty = no restriction.'}</p>
                </FormGroup>
                {form.allowed_identifier_patterns.length > 0 && (
                  <FormGroup label="Match mode" fieldId="pf-match-mode">
                    <Radio id="match-all" name="match-mode" label="All identifiers must match (AND)"
                      isChecked={form.identifier_match_all}
                      onChange={() => set('identifier_match_all', true)} />
                    <Radio id="match-any" name="match-mode" label="At least one identifier must match (OR)"
                      isChecked={!form.identifier_match_all}
                      onChange={() => set('identifier_match_all', false)} />
                  </FormGroup>
                )}
              </FormSection>
            </CardBody>
          </Card>

          {/* ── Authorization ────────────────────────────────────── */}
          <Card>
            <CardBody>
              <FormSection title="Authorization">
                <FormGroup fieldId="pf-grant">
                  <Checkbox id="pf-grant" label="Require account profile grant"
                    isChecked={form.require_account_grant}
                    onChange={(_e, checked) => set('require_account_grant', checked)}
                    description="Account must have this profile in its profile_grants list to place orders." />
                </FormGroup>
                <FormGroup label="Auth Hook" fieldId="pf-hook">
                  <TextInput id="pf-hook" value={form.auth_hook ?? ''}
                    onChange={(_e, v) => set('auth_hook', v || null)}
                    placeholder="/usr/local/lib/akamu/hooks/authorize.sh" style={{ maxWidth: '480px' }} />
                  <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>Path to an external script that receives order details on stdin and exits 0 to allow.</p>
                </FormGroup>
                {form.auth_hook && (
                  <FormGroup label="Hook Timeout (seconds)" fieldId="pf-hook-timeout">
                    <TextInput id="pf-hook-timeout" type="number" value={String(form.auth_hook_timeout_secs)}
                      onChange={(_e, v) => set('auth_hook_timeout_secs', parseInt(v, 10) || 30)}
                      style={{ maxWidth: '8rem' }} />
                  </FormGroup>
                )}
              </FormSection>
            </CardBody>
          </Card>

          {/* ── CA Restriction ───────────────────────────────────── */}
          <Card>
            <CardBody>
              <FormSection title="CA Restriction">
                <FormGroup label="Allowed CAs" fieldId="pf-ca-ids">
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginBottom: '0.5rem' }}>
                    {cas.map(ca => (
                      <Checkbox key={ca.id} id={`ca-${ca.id}`} label={ca.id}
                        isChecked={form.ca_ids.includes(ca.id)}
                        onChange={(_e, checked) =>
                          set('ca_ids', checked ? [...form.ca_ids, ca.id] : form.ca_ids.filter(x => x !== ca.id))
                        } />
                    ))}
                    {cas.length === 0 && (
                      <StringList label="CA IDs" values={form.ca_ids}
                        placeholder="ca-id" onChange={v => set('ca_ids', v)} />
                    )}
                  </div>
                  <p style={{ fontSize: '0.75rem', color: '#6a6e73', marginTop: '0.25rem' }}>Restrict this profile to specific CAs. Empty = available on all CAs.</p>
                </FormGroup>
              </FormSection>
            </CardBody>
          </Card>

          {/* ── MTC ─────────────────────────────────────────────── */}
          <Card>
            <CardBody>
              <FormSection title="Merkle Tree Certificates">
                <FormGroup fieldId="pf-mtc">
                  <Checkbox id="pf-mtc" label="Issue as MTC StandaloneCertificate"
                    isChecked={form.issue_as_mtc}
                    onChange={(_e, checked) => set('issue_as_mtc', checked)}
                    description="Requires [mtc] to be enabled in server configuration." />
                </FormGroup>
              </FormSection>
            </CardBody>
          </Card>

          <ActionGroup>
            <Button type="submit" variant="primary" isLoading={saving} isDisabled={saving || (createMode && !formId.trim())}>
              {createMode ? 'Create' : 'Save'}
            </Button>
            <Button variant="link" onClick={() => navigate(backPath)} isDisabled={saving}>Cancel</Button>
          </ActionGroup>
        </Form>
      </PageSection>
    </>
  );
}
