import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  PageSection,
  PageSectionVariants,
  Title,
  Spinner,
  Alert,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
  Button,
  Flex,
  FlexItem,
  Label,
  LabelGroup,
} from '@patternfly/react-core';
import { getProfile, ProfileEntry } from '../../api/profiles';
import { useAuth, hasRole } from '../../auth/AuthContext';

const KEY_USAGE_NAMES: Record<number, string> = {
  0: 'digitalSignature', 1: 'nonRepudiation', 2: 'keyEncipherment',
  3: 'dataEncipherment', 4: 'keyAgreement', 5: 'keyCertSign',
  6: 'cRLSign', 7: 'encipherOnly', 8: 'decipherOnly',
};

function keyUsageLabels(bits: number): string[] {
  return Object.entries(KEY_USAGE_NAMES)
    .filter(([bit]) => bits & (1 << Number(bit)))
    .map(([, name]) => name);
}

function Tags({ items }: { items: string[] }) {
  if (!items.length) return <>—</>;
  return (
    <LabelGroup>
      {items.map(i => <Label key={i} variant="outline">{i}</Label>)}
    </LabelGroup>
  );
}

export default function ProfileDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { role } = useAuth();
  const isAdmin = hasRole(role, 'administrator');

  const [data, setData] = useState<ProfileEntry | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    getProfile(id)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [id]);

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Link to="/profiles" style={{ fontSize: '0.875rem' }}>← Back to Profiles</Link>
        <Flex style={{ marginTop: '0.5rem' }} alignItems={{ default: 'alignItemsCenter' }}>
          <FlexItem>
            <Title headingLevel="h1">Profile: {id}</Title>
          </FlexItem>
          {isAdmin && data && (
            <FlexItem>
              <Button variant="secondary" onClick={() => navigate(`/profiles/${id}/edit`)}>Edit</Button>
            </FlexItem>
          )}
        </Flex>
      </PageSection>
      <PageSection>
        {loading && <Spinner />}
        {error && <Alert variant="danger" title={error} isInline />}
        {data && (
          <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: '720px' }}>
            <DescriptionListGroup>
              <DescriptionListTerm>ID</DescriptionListTerm>
              <DescriptionListDescription>{data.id}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Description</DescriptionListTerm>
              <DescriptionListDescription>{data.description || '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Validity (days)</DescriptionListTerm>
              <DescriptionListDescription>{data.validity_days ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Hash Algorithm</DescriptionListTerm>
              <DescriptionListDescription>{data.hash_alg ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Key Usage</DescriptionListTerm>
              <DescriptionListDescription>
                {data.key_usage_bits
                  ? <Tags items={keyUsageLabels(data.key_usage_bits)} />
                  : <span style={{ color: '#666' }}>omitted (extension not included)</span>}
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Extended Key Usages</DescriptionListTerm>
              <DescriptionListDescription>
                <Tags items={data.extended_key_usages ?? []} />
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>CRL Distribution Point</DescriptionListTerm>
              <DescriptionListDescription>{data.crl_url ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>OCSP Responder</DescriptionListTerm>
              <DescriptionListDescription>{data.ocsp_url ?? '—'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Certificate Policies</DescriptionListTerm>
              <DescriptionListDescription>
                {data.certificate_policies?.length
                  ? (
                    <ul style={{ margin: 0, paddingLeft: '1.25rem' }}>
                      {data.certificate_policies.map(([oid, cps], i) => (
                        <li key={i}>{oid}{cps ? ` — ${cps}` : ''}</li>
                      ))}
                    </ul>
                  )
                  : '—'}
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Allowed Key Types</DescriptionListTerm>
              <DescriptionListDescription>
                <Tags items={data.allowed_key_types ?? []} />
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Identifier Patterns</DescriptionListTerm>
              <DescriptionListDescription>
                {data.allowed_identifier_patterns?.length
                  ? <Tags items={data.allowed_identifier_patterns} />
                  : '—'}
              </DescriptionListDescription>
            </DescriptionListGroup>
            {(data.allowed_identifier_patterns?.length ?? 0) > 0 && (
              <DescriptionListGroup>
                <DescriptionListTerm>Identifier Match Mode</DescriptionListTerm>
                <DescriptionListDescription>
                  {data.identifier_match_all ? 'All must match (AND)' : 'Any must match (OR)'}
                </DescriptionListDescription>
              </DescriptionListGroup>
            )}
            <DescriptionListGroup>
              <DescriptionListTerm>Require Account Grant</DescriptionListTerm>
              <DescriptionListDescription>{data.require_account_grant ? 'Yes' : 'No'}</DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Auth Hook</DescriptionListTerm>
              <DescriptionListDescription>
                {data.auth_hook
                  ? <><code>{data.auth_hook}</code> (timeout: {data.auth_hook_timeout_secs ?? 30}s)</>
                  : '—'}
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Allowed CAs</DescriptionListTerm>
              <DescriptionListDescription>
                <Tags items={data.ca_ids ?? []} />
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Issue as MTC</DescriptionListTerm>
              <DescriptionListDescription>{data.issue_as_mtc ? 'Yes' : 'No'}</DescriptionListDescription>
            </DescriptionListGroup>
          </DescriptionList>
        )}
      </PageSection>
    </>
  );
}
