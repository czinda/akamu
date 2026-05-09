import React, { useEffect, useState } from 'react';
import {
  PageSection,
  PageSectionVariants,
  Title,
  Card,
  CardBody,
  CardTitle,
  Grid,
  GridItem,
  Spinner,
  Alert,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
  Label,
} from '@patternfly/react-core';
import { getStats, ServerStats } from '../../api/stats';
import { useAuth } from '../../auth/AuthContext';

function StatRow({ label, value }: { label: string; value: number | string }) {
  return (
    <DescriptionListGroup>
      <DescriptionListTerm>{label}</DescriptionListTerm>
      <DescriptionListDescription>{value}</DescriptionListDescription>
    </DescriptionListGroup>
  );
}

function fmtUptime(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  const parts: string[] = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  parts.push(`${s}s`);
  return parts.join(' ');
}

export default function Dashboard() {
  const { role } = useAuth();
  const canSeeAudit = role === 'administrator' || role === 'auditor';
  const [stats, setStats] = useState<ServerStats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getStats()
      .then(setStats)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load stats'));
  }, []);

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Title headingLevel="h1">Dashboard</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        {!stats && !error && <Spinner />}
        {stats && (
          <Grid hasGutter>
            <GridItem span={4}>
              <Card>
                <CardTitle>
                  Certificates
                  {stats.ca_scope && (
                    <Label color="blue" isCompact style={{ marginLeft: '0.5rem' }}>
                      CA: {stats.ca_scope}
                    </Label>
                  )}
                </CardTitle>
                <CardBody>
                  <DescriptionList isHorizontal columnModifier={{ default: '1Col' }}>
                    <StatRow label="Total" value={stats.certs.total} />
                    <StatRow label="Active" value={stats.certs.active} />
                    <StatRow label="Revoked" value={stats.certs.revoked} />
                  </DescriptionList>
                </CardBody>
              </Card>
            </GridItem>
            <GridItem span={4}>
              <Card>
                <CardTitle>Accounts</CardTitle>
                <CardBody>
                  <DescriptionList isHorizontal columnModifier={{ default: '1Col' }}>
                    <StatRow label="Total" value={stats.accounts.total} />
                    <StatRow label="Active" value={stats.accounts.active} />
                    <StatRow label="Inactive" value={stats.accounts.total - stats.accounts.active} />
                  </DescriptionList>
                </CardBody>
              </Card>
            </GridItem>
            <GridItem span={4}>
              <Card>
                <CardTitle>EAB Keys</CardTitle>
                <CardBody>
                  <DescriptionList isHorizontal columnModifier={{ default: '1Col' }}>
                    <StatRow label="Total" value={stats.eab_keys.total} />
                    <StatRow label="Used (ACME)" value={stats.eab_keys.used} />
                    <StatRow label="Bound (reserved)" value={stats.eab_keys.bound} />
                    <StatRow label="Free" value={stats.eab_keys.free} />
                  </DescriptionList>
                </CardBody>
              </Card>
            </GridItem>
            {canSeeAudit && (
              <GridItem span={4}>
                <Card>
                  <CardTitle>Audit Events</CardTitle>
                  <CardBody>
                    <DescriptionList isHorizontal columnModifier={{ default: '1Col' }}>
                      <StatRow label="Total" value={stats.audit_events.total} />
                    </DescriptionList>
                  </CardBody>
                </Card>
              </GridItem>
            )}
            <GridItem span={4}>
              <Card>
                <CardTitle>Server</CardTitle>
                <CardBody>
                  <DescriptionList isHorizontal columnModifier={{ default: '1Col' }}>
                    <StatRow label="Version" value={stats.server_version} />
                    <StatRow label="Uptime" value={fmtUptime(stats.uptime_secs)} />
                  </DescriptionList>
                </CardBody>
              </Card>
            </GridItem>
          </Grid>
        )}
      </PageSection>
    </>
  );
}
