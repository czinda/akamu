import React, { useEffect, useState, useCallback } from 'react';
import {
  PageSection,
  PageSectionVariants,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  Spinner,
  Alert,
  EmptyState,
  EmptyStateBody,
  Select,
  SelectOption,
  Pagination,
} from '@patternfly/react-core';
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
} from '@patternfly/react-table';
import { listOrders, OrderRow, OrderListParams } from '../../api/orders';

const PAGE_SIZE = 20;

export default function Orders() {
  const [orders, setOrders] = useState<OrderRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [statusOpen, setStatusOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: OrderListParams = { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE };
      if (statusFilter) params.status = statusFilter;
      const result = await listOrders(params);
      setOrders(result.orders);
      setTotal(result.total ?? result.orders.length);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load orders');
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter]);

  useEffect(() => { load(); }, [load]);

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <Title headingLevel="h1">Orders</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <Select
                isOpen={statusOpen}
                onToggle={(_e, v) => setStatusOpen(v)}
                onSelect={(_e, v) => { setStatusFilter(v as string); setStatusOpen(false); setPage(1); }}
                selections={statusFilter || 'All statuses'}
                placeholderText="All statuses"
              >
                <SelectOption value="">All statuses</SelectOption>
                <SelectOption value="pending">pending</SelectOption>
                <SelectOption value="ready">ready</SelectOption>
                <SelectOption value="processing">processing</SelectOption>
                <SelectOption value="valid">valid</SelectOption>
                <SelectOption value="invalid">invalid</SelectOption>
              </Select>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
        {loading && <Spinner />}
        {!loading && orders.length === 0 && (
          <EmptyState><EmptyStateBody>No orders found.</EmptyStateBody></EmptyState>
        )}
        {!loading && orders.length > 0 && (
          <Table aria-label="Orders">
            <Thead>
              <Tr>
                <Th>ID</Th>
                <Th>Account</Th>
                <Th>Status</Th>
                <Th>Identifiers</Th>
                <Th>Created</Th>
                <Th>Expires</Th>
              </Tr>
            </Thead>
            <Tbody>
              {orders.map(order => (
                <Tr key={order.id}>
                  <Td>{order.id}</Td>
                  <Td>{order.account_id}</Td>
                  <Td>{order.status}</Td>
                  <Td>{Array.isArray(order.identifiers) ? order.identifiers.join(', ') : order.identifiers}</Td>
                  <Td>{order.created_at}</Td>
                  <Td>{order.expires_at ?? '—'}</Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
        <Pagination
          itemCount={total}
          perPage={PAGE_SIZE}
          page={page}
          onSetPage={(_e, p) => setPage(p)}
        />
      </PageSection>
    </>
  );
}
