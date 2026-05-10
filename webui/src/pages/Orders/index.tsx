import { useEffect, useState, useCallback } from 'react';
import {
  PageSection,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  ToolbarGroup,
  Button,
  TextInput,
  Spinner,
  Alert,
  EmptyState,
  EmptyStateBody,
  Pagination,
  FormSelect,
  FormSelectOption,
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
import { useAuth } from '../../auth/AuthContext';
import { fmtTs, fmtIdentifiers } from '../../utils';
import { ObjLink } from '../../components/ObjLink';

const PAGE_SIZE = 20;

interface FilterDraft {
  account_id: string;
  ca_id: string;
  status: string;
}

const EMPTY_DRAFT: FilterDraft = { account_id: '', ca_id: '', status: '' };

export default function Orders() {
  const navigate = useNavigate();
  const { role } = useAuth();
  const isCaRa = role === 'ca_ra';

  const [orders, setOrders] = useState<OrderRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [draft, setDraft] = useState<FilterDraft>(EMPTY_DRAFT);
  const [applied, setApplied] = useState<FilterDraft>(EMPTY_DRAFT);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: OrderListParams = { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE };
      if (applied.account_id) params.account_id = applied.account_id;
      if (applied.ca_id)      params.ca_id      = applied.ca_id;
      if (applied.status)     params.status     = applied.status;
      const result = await listOrders(params);
      setOrders(result.orders);
      setTotal(result.total ?? result.orders.length);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load orders');
    } finally {
      setLoading(false);
    }
  }, [page, applied]);

  useEffect(() => { load(); }, [load]);

  function handleSearch() {
    setApplied(draft);
    setPage(1);
  }

  function handleClear() {
    setDraft(EMPTY_DRAFT);
    setApplied(EMPTY_DRAFT);
    setPage(1);
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter') handleSearch();
  }

  const inputStyle = { width: '160px' };

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Orders</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarGroup>
              <ToolbarItem>
                <TextInput
                  placeholder="Account ID"
                  value={draft.account_id}
                  onChange={(_e, v) => setDraft(d => ({ ...d, account_id: v }))}
                  onKeyDown={handleKeyDown}
                  style={inputStyle}
                  aria-label="Filter by account ID"
                />
              </ToolbarItem>
              {!isCaRa && (
                <ToolbarItem>
                  <TextInput
                    placeholder="CA ID"
                    value={draft.ca_id}
                    onChange={(_e, v) => setDraft(d => ({ ...d, ca_id: v }))}
                    onKeyDown={handleKeyDown}
                    style={inputStyle}
                    aria-label="Filter by CA ID"
                  />
                </ToolbarItem>
              )}
              <ToolbarItem>
                <FormSelect
                  value={draft.status}
                  onChange={(_e, v) => setDraft(d => ({ ...d, status: v }))}
                  aria-label="Filter by status"
                >
                  <FormSelectOption value="" label="All statuses" />
                  <FormSelectOption value="pending" label="pending" />
                  <FormSelectOption value="ready" label="ready" />
                  <FormSelectOption value="processing" label="processing" />
                  <FormSelectOption value="valid" label="valid" />
                  <FormSelectOption value="invalid" label="invalid" />
                </FormSelect>
              </ToolbarItem>
              <ToolbarItem>
                <Button variant="primary" onClick={handleSearch}>Search</Button>
              </ToolbarItem>
              <ToolbarItem>
                <Button variant="link" onClick={handleClear}>Clear</Button>
              </ToolbarItem>
            </ToolbarGroup>
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
                  <Td><ObjLink type="account" id={order.account_id} /></Td>
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
