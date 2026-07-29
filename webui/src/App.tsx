import React, { Component, type ReactNode, Suspense, useCallback, useMemo } from 'react';
import { Routes, Route, Navigate, NavLink, Outlet, useLocation, Link } from 'react-router-dom';
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
import { useAuth, type Role } from './auth/AuthContext';
import { logout as apiLogout } from './api/session';
import { NAV_ITEMS, canAccess, accessForPath, type RouteAccess } from './nav';

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

function RouteGuard({ access, children }: { access: RouteAccess; children: React.ReactElement }) {
  const { role } = useAuth();
  if (!canAccess(role, access)) return <Navigate to="/" replace />;
  return children;
}

function NotFound() {
  return (
    <div style={{ textAlign: 'center', padding: '4rem 1rem' }}>
      <h1>404 — Page Not Found</h1>
      <p>The page you requested does not exist.</p>
      <Link to="/">Back to Dashboard</Link>
    </div>
  );
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
  return (
    <PageSidebar>
      <PageSidebarBody>
        <Nav>
          <NavList>
            {NAV_ITEMS.filter(item => canAccess(role, item.access)).map(item => (
              <NavItem key={item.path}>
                <NavLink to={item.path} end={item.end}>{item.label}</NavLink>
              </NavItem>
            ))}
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
          <RouteGuard access={accessForPath('/audit')}><AuditLog /></RouteGuard>
        } />
        <Route path="/eab" element={
          <RouteGuard access={accessForPath('/eab')}><EabKeys /></RouteGuard>
        } />
        <Route path="/delegations" element={
          <RouteGuard access={accessForPath('/delegations')}><Delegations /></RouteGuard>
        } />
        <Route path="/profiles" element={
          <RouteGuard access={accessForPath('/profiles')}><Profiles /></RouteGuard>
        } />
        <Route path="/cas" element={
          <RouteGuard access={accessForPath('/cas')}><CAs /></RouteGuard>
        } />
        <Route path="/cross-certs" element={
          <RouteGuard access={accessForPath('/cross-certs')}><CrossCerts /></RouteGuard>
        } />
        <Route path="/mtc" element={
          <RouteGuard access={accessForPath('/mtc')}><MtcOverview /></RouteGuard>
        } />
        <Route path="/operators" element={
          <RouteGuard access={accessForPath('/operators')}><Operators /></RouteGuard>
        } />
        <Route path="/config" element={
          <RouteGuard access={accessForPath('/config')}><ServerConfig /></RouteGuard>
        } />
        <Route path="/certs/:id" element={<CertDetail />} />
        <Route path="/orders/:id" element={<OrderDetail />} />
        <Route path="/accounts/:id" element={<AccountDetail />} />
        <Route path="/eab/:kid" element={<RouteGuard access={accessForPath('/eab')}><EabKeyDetail /></RouteGuard>} />
        <Route path="/profiles/:id" element={<RouteGuard access={accessForPath('/profiles')}><ProfileDetail /></RouteGuard>} />
        <Route path="/profiles/:id/edit" element={<RouteGuard access={{ minRole: 'administrator' }}><ProfileEdit /></RouteGuard>} />
        <Route path="/profiles/new" element={<RouteGuard access={{ minRole: 'administrator' }}><ProfileEdit createMode /></RouteGuard>} />
        <Route path="/delegations/:id" element={<RouteGuard access={accessForPath('/delegations')}><DelegationDetail /></RouteGuard>} />
        <Route path="/cas/:id" element={<RouteGuard access={accessForPath('/cas')}><CADetail /></RouteGuard>} />
        <Route path="/cross-certs/:id" element={<RouteGuard access={accessForPath('/cross-certs')}><CrossCertDetail /></RouteGuard>} />
        <Route path="/mtc/:caId" element={<RouteGuard access={accessForPath('/mtc')}><MtcDetail /></RouteGuard>} />
        <Route path="/mtc/:caId/landmarks/:seq" element={<RouteGuard access={accessForPath('/mtc')}><MtcLandmarkDetail /></RouteGuard>} />
        <Route path="/operators/:id" element={<RouteGuard access={accessForPath('/operators')}><OperatorDetail /></RouteGuard>} />
        <Route path="/operators/:id/edit" element={<RouteGuard access={accessForPath('/operators')}><OperatorEdit /></RouteGuard>} />
        <Route path="/operators/new" element={<RouteGuard access={accessForPath('/operators')}><OperatorEdit createMode /></RouteGuard>} />
        <Route path="/delegations/:id/edit" element={<RouteGuard access={{ minRole: 'ca_operations' }}><DelegationEdit /></RouteGuard>} />
        <Route path="/delegations/new" element={<RouteGuard access={{ minRole: 'ca_operations' }}><DelegationEdit createMode /></RouteGuard>} />
        <Route path="/policies" element={
          <RouteGuard access={accessForPath('/policies')}><Policies /></RouteGuard>
        } />
        <Route path="/policies/new" element={
          <RouteGuard access={{ anyOf: ['administrator', 'ca_operations'] }}><PolicyEdit createMode /></RouteGuard>
        } />
        <Route path="/policies/:id/edit" element={
          <RouteGuard access={{ anyOf: ['administrator', 'ca_operations'] }}><PolicyEdit /></RouteGuard>
        } />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
