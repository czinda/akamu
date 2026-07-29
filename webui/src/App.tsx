import React, { Component, type ReactNode, Suspense, useCallback, useMemo } from 'react';
import { Routes, Route, Navigate, NavLink, Outlet, useLocation } from 'react-router-dom';
import {
  Page,
  Masthead,
  MastheadMain,
  MastheadBrand,
  MastheadContent,
  Nav,
  NavList,
  NavItem,
  PageSidebar,
  PageSidebarBody,
  Button,
  Label,
  Flex,
  FlexItem,
  Spinner,
} from '@patternfly/react-core';
import { useAuth, hasRole, Role } from './auth/AuthContext';
import { logout as apiLogout } from './api/session';

const LoginPage = React.lazy(() => import('./auth/LoginPage'));
const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const Certificates = React.lazy(() => import('./pages/Certificates'));
const Orders = React.lazy(() => import('./pages/Orders'));
const Accounts = React.lazy(() => import('./pages/Accounts'));
const EabKeys = React.lazy(() => import('./pages/EabKeys'));
const Profiles = React.lazy(() => import('./pages/Profiles'));
const Delegations = React.lazy(() => import('./pages/Delegations'));
const CAs = React.lazy(() => import('./pages/CAs'));
const CrossCerts = React.lazy(() => import('./pages/CrossCerts'));
const Operators = React.lazy(() => import('./pages/Operators'));
const AuditLog = React.lazy(() => import('./pages/AuditLog'));
const ServerConfig = React.lazy(() => import('./pages/ServerConfig'));
const MtcOverview = React.lazy(() => import('./pages/MTC'));
const MtcDetail = React.lazy(() => import('./pages/MTC/Detail'));
const MtcLandmarkDetail = React.lazy(() => import('./pages/MTC/LandmarkDetail'));
const CertDetail = React.lazy(() => import('./pages/Certificates/Detail'));
const OrderDetail = React.lazy(() => import('./pages/Orders/Detail'));
const AccountDetail = React.lazy(() => import('./pages/Accounts/Detail'));
const EabKeyDetail = React.lazy(() => import('./pages/EabKeys/Detail'));
const ProfileDetail = React.lazy(() => import('./pages/Profiles/Detail'));
const ProfileEdit = React.lazy(() => import('./pages/Profiles/Edit'));
const OperatorEdit = React.lazy(() => import('./pages/Operators/Edit'));
const DelegationEdit = React.lazy(() => import('./pages/Delegations/Edit'));
const DelegationDetail = React.lazy(() => import('./pages/Delegations/Detail'));
const CADetail = React.lazy(() => import('./pages/CAs/Detail'));
const CrossCertDetail = React.lazy(() => import('./pages/CrossCerts/Detail'));
const Policies = React.lazy(() => import('./pages/Policies'));
const PolicyEdit = React.lazy(() => import('./pages/Policies/Edit'));
const OperatorDetail = React.lazy(() => import('./pages/Operators/Detail'));

class PageErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  override render() {
    if (this.state.error) {
      return (
        <div style={{ padding: '2rem' }}>
          <h2>Something went wrong</h2>
          <p style={{ color: '#c9190b', fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
            {this.state.error.message}
          </p>
          <button onClick={() => this.setState({ error: null })}>Try again</button>
        </div>
      );
    }
    return this.props.children;
  }
}

function LocationResetErrorBoundary({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return <PageErrorBoundary key={pathname}>{children}</PageErrorBoundary>;
}

function RequireRole({ minRole, children }: { minRole: Role; children: React.ReactElement }) {
  const { role } = useAuth();
  if (!hasRole(role, minRole)) return <Navigate to="/" replace />;
  return children;
}

function RequireAnyRole({ roles, children }: { roles: Role[]; children: React.ReactElement }) {
  const { role } = useAuth();
  if (!role || !roles.includes(role)) return <Navigate to="/" replace />;
  return children;
}

function AppHeader({ onLogout }: { onLogout: () => void }) {
  const { role, operatorName } = useAuth();

  return (
    <Masthead>
      <MastheadMain>
        <MastheadBrand>Akamu PKI</MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Flex>
          {role && <FlexItem><Label color="blue">{role}</Label></FlexItem>}
          {operatorName && <FlexItem>{operatorName}</FlexItem>}
          <FlexItem>
            <Button variant="link" onClick={onLogout}>Logout</Button>
          </FlexItem>
        </Flex>
      </MastheadContent>
    </Masthead>
  );
}

function AppSidebar({ role }: { role: Role | null }) {
  const isAtLeastCaRa = hasRole(role, 'ca_ra');
  const isAtLeastCaOps = hasRole(role, 'ca_operations');
  const isAdmin = hasRole(role, 'administrator');
  const canSeeAudit = role === 'administrator' || role === 'auditor';
  const canSeeCrossCerts = role === 'administrator' || role === 'ca_operations' || role === 'auditor';
  const canSeeMtc = role === 'administrator' || role === 'ca_operations' || role === 'auditor';
  const canSeePolicies = role === 'administrator' || role === 'ca_operations' || role === 'auditor';

  return (
    <PageSidebar>
      <PageSidebarBody>
        <Nav>
          <NavList>
            <NavItem><NavLink to="/" end>Dashboard</NavLink></NavItem>
            <NavItem><NavLink to="/certs">Certificates</NavLink></NavItem>
            <NavItem><NavLink to="/orders">Orders</NavLink></NavItem>
            <NavItem><NavLink to="/accounts">Accounts</NavLink></NavItem>
            {canSeeAudit && <NavItem><NavLink to="/audit">Audit Log</NavLink></NavItem>}
            {isAtLeastCaRa && (
              <>
                <NavItem><NavLink to="/eab">EAB Keys</NavLink></NavItem>
                <NavItem><NavLink to="/delegations">Delegations</NavLink></NavItem>
                <NavItem><NavLink to="/profiles">Profiles</NavLink></NavItem>
              </>
            )}
            {isAtLeastCaOps && <NavItem><NavLink to="/cas">CAs</NavLink></NavItem>}
            {canSeeCrossCerts && <NavItem><NavLink to="/cross-certs">Cross-Certs</NavLink></NavItem>}
            {canSeeMtc && <NavItem><NavLink to="/mtc">Transparency Log</NavLink></NavItem>}
            {canSeePolicies && <NavItem><NavLink to="/policies">Policies</NavLink></NavItem>}
            {isAdmin && (
              <>
                <NavItem><NavLink to="/operators">Operators</NavLink></NavItem>
                <NavItem><NavLink to="/config">Server Config</NavLink></NavItem>
              </>
            )}
          </NavList>
        </Nav>
      </PageSidebarBody>
    </PageSidebar>
  );
}

const MemoSidebar = React.memo(AppSidebar);
const MemoHeader = React.memo(AppHeader);

function AuthenticatedLayout() {
  const { token, role, clearAuth } = useAuth();

  const handleLogout = useCallback(async () => {
    await apiLogout();
    clearAuth();
    window.location.href = '/ui/login';
  }, [clearAuth]);

  const masthead = useMemo(() => <MemoHeader onLogout={handleLogout} />, [handleLogout]);
  const sidebar = useMemo(() => <MemoSidebar role={role} />, [role]);

  if (!token) return <Navigate to="/login" replace />;
  if (!role) return <Spinner />;

  return (
    <Page
      masthead={masthead}
      sidebar={sidebar}
      isManagedSidebar
    >
      <LocationResetErrorBoundary>
        <Suspense fallback={<Spinner />}>
          <Outlet />
        </Suspense>
      </LocationResetErrorBoundary>
    </Page>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Suspense fallback={<Spinner />}><LoginPage /></Suspense>} />
      <Route element={<AuthenticatedLayout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/certs" element={<Certificates />} />
        <Route path="/orders" element={<Orders />} />
        <Route path="/accounts" element={<Accounts />} />
        <Route path="/audit" element={
          <RequireAnyRole roles={['administrator', 'auditor']}><AuditLog /></RequireAnyRole>
        } />
        <Route path="/eab" element={
          <RequireRole minRole="ca_ra"><EabKeys /></RequireRole>
        } />
        <Route path="/delegations" element={
          <RequireRole minRole="ca_ra"><Delegations /></RequireRole>
        } />
        <Route path="/profiles" element={
          <RequireRole minRole="ca_ra"><Profiles /></RequireRole>
        } />
        <Route path="/cas" element={
          <RequireRole minRole="ca_operations"><CAs /></RequireRole>
        } />
        <Route path="/cross-certs" element={
          <RequireAnyRole roles={['administrator', 'ca_operations', 'auditor']}><CrossCerts /></RequireAnyRole>
        } />
        <Route path="/mtc" element={
          <RequireAnyRole roles={['administrator', 'ca_operations', 'auditor']}><MtcOverview /></RequireAnyRole>
        } />
        <Route path="/operators" element={
          <RequireRole minRole="administrator"><Operators /></RequireRole>
        } />
        <Route path="/config" element={
          <RequireRole minRole="administrator"><ServerConfig /></RequireRole>
        } />
        <Route path="/certs/:id" element={<CertDetail />} />
        <Route path="/orders/:id" element={<OrderDetail />} />
        <Route path="/accounts/:id" element={<AccountDetail />} />
        <Route path="/eab/:kid" element={<RequireRole minRole="ca_ra"><EabKeyDetail /></RequireRole>} />
        <Route path="/profiles/:id" element={<RequireRole minRole="ca_ra"><ProfileDetail /></RequireRole>} />
        <Route path="/profiles/:id/edit" element={<RequireRole minRole="administrator"><ProfileEdit /></RequireRole>} />
        <Route path="/profiles/new" element={<RequireRole minRole="administrator"><ProfileEdit createMode /></RequireRole>} />
        <Route path="/delegations/:id" element={<RequireRole minRole="ca_ra"><DelegationDetail /></RequireRole>} />
        <Route path="/cas/:id" element={<RequireRole minRole="ca_operations"><CADetail /></RequireRole>} />
        <Route path="/cross-certs/:id" element={<RequireAnyRole roles={['administrator', 'ca_operations', 'auditor']}><CrossCertDetail /></RequireAnyRole>} />
        <Route path="/mtc/:caId" element={<RequireAnyRole roles={['administrator', 'ca_operations', 'auditor']}><MtcDetail /></RequireAnyRole>} />
        <Route path="/mtc/:caId/landmarks/:seq" element={<RequireAnyRole roles={['administrator', 'ca_operations', 'auditor']}><MtcLandmarkDetail /></RequireAnyRole>} />
        <Route path="/operators/:id" element={<RequireRole minRole="administrator"><OperatorDetail /></RequireRole>} />
        <Route path="/operators/:id/edit" element={<RequireRole minRole="administrator"><OperatorEdit /></RequireRole>} />
        <Route path="/operators/new" element={<RequireRole minRole="administrator"><OperatorEdit createMode /></RequireRole>} />
        <Route path="/delegations/:id/edit" element={<RequireRole minRole="ca_operations"><DelegationEdit /></RequireRole>} />
        <Route path="/delegations/new" element={<RequireRole minRole="ca_operations"><DelegationEdit createMode /></RequireRole>} />
        <Route path="/policies" element={
          <RequireAnyRole roles={['administrator', 'ca_operations', 'auditor']}><Policies /></RequireAnyRole>
        } />
        <Route path="/policies/new" element={
          <RequireAnyRole roles={['administrator', 'ca_operations']}><PolicyEdit createMode /></RequireAnyRole>
        } />
        <Route path="/policies/:id/edit" element={
          <RequireAnyRole roles={['administrator', 'ca_operations']}><PolicyEdit /></RequireAnyRole>
        } />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
