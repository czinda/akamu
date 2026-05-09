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
} from '@patternfly/react-core';
import { getStats, ServerStats } from '../../api/stats';

export default function Dashboard() {
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
            <GridItem span={3}>
              <Card>
                <CardTitle>Certificates</CardTitle>
                <CardBody>
                  <div>Total: {stats.certificates_total}</div>
                  <div>Valid: {stats.certificates_valid}</div>
                  <div>Revoked: {stats.certificates_revoked}</div>
                  <div>Expired: {stats.certificates_expired}</div>
                </CardBody>
              </Card>
            </GridItem>
            <GridItem span={3}>
              <Card>
                <CardTitle>Orders</CardTitle>
                <CardBody>
                  <div>Pending: {stats.orders_pending}</div>
                  <div>Ready: {stats.orders_ready}</div>
                  <div>Processing: {stats.orders_processing}</div>
                  <div>Valid: {stats.orders_valid}</div>
                  <div>Invalid: {stats.orders_invalid}</div>
                </CardBody>
              </Card>
            </GridItem>
            <GridItem span={3}>
              <Card>
                <CardTitle>Accounts</CardTitle>
                <CardBody>
                  <div>Active: {stats.accounts_active}</div>
                  <div>Deactivated: {stats.accounts_deactivated}</div>
                  <div>Revoked: {stats.accounts_revoked}</div>
                </CardBody>
              </Card>
            </GridItem>
          </Grid>
        )}
      </PageSection>
    </>
  );
}
