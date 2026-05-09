import { useEffect, useState, useCallback } from 'react';
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
import { useNavigate } from 'react-router-dom';
import { listOrders, OrderRow, OrderListParams } from '../../api/orders';
import { fmtTs, fmtIdentifiers } from '../../utils';

const PAGE_SIZE = 20;

export default function Orders() {
  const navigate = useNavigate();
  const [orders, setOrders] = useState<OrderRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');

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
      <PageSection>
        <Title headingLevel="h1">Orders</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <select
                value={statusFilter}
                onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
                style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: '4px', fontSize: 'inherit' }}
              >
                <option value="">All statuses</option>
                <option value="pending">pending</option>
                <option value="ready">ready</option>
                <option value="processing">processing</option>
                <option value="valid">valid</option>
                <option value="invalid">invalid</option>
              </select>
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
                <Th>Details</Th>
              </Tr>
            </Thead>
            <Tbody>
              {orders.map(order => (
                <Tr key={order.id}>
                  <Td>{order.id}</Td>
                  <Td>{order.account_id}</Td>
                  <Td>{order.status}</Td>
                  <Td>{fmtIdentifiers(order.identifiers)}</Td>
                  <Td>{fmtTs(order.created)}</Td>
                  <Td>{fmtTs(order.expires)}</Td>
                  <Td><Button variant="plain" size="sm" onClick={() => navigate(`/orders/${order.id}`)}>View</Button></Td>
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
