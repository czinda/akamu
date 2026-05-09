import React from 'react';
import { Routes, Route, Navigate, NavLink, Outlet, useNavigate } from 'react-router-dom';
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
import LoginPage from './auth/LoginPage';
import Dashboard from './pages/Dashboard';
import Certificates from './pages/Certificates';
import Orders from './pages/Orders';
import Accounts from './pages/Accounts';
import EabKeys from './pages/EabKeys';
import Profiles from './pages/Profiles';
import Delegations from './pages/Delegations';
import CAs from './pages/CAs';
import CrossCerts from './pages/CrossCerts';
import Operators from './pages/Operators';
import AuditLog from './pages/AuditLog';
import ServerConfig from './pages/ServerConfig';

function RequireRole({ minRole, children }: { minRole: Role; children: React.ReactElement }) {
  const { role } = useAuth();
  if (!hasRole(role, minRole)) return <Navigate to="/" replace />;
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
  const isAdmin = hasRole(role, 'administrator');

  return (
    <PageSidebar>
      <PageSidebarBody>
        <Nav>
          <NavList>
            <NavItem><NavLink to="/" end>Dashboard</NavLink></NavItem>
            <NavItem><NavLink to="/certs">Certificates</NavLink></NavItem>
            <NavItem><NavLink to="/orders">Orders</NavLink></NavItem>
            <NavItem><NavLink to="/accounts">Accounts</NavLink></NavItem>
            <NavItem><NavLink to="/audit">Audit Log</NavLink></NavItem>
            {isAtLeastCaRa && (
              <>
                <NavItem><NavLink to="/eab">EAB Keys</NavLink></NavItem>
                <NavItem><NavLink to="/delegations">Delegations</NavLink></NavItem>
                <NavItem><NavLink to="/profiles">Profiles</NavLink></NavItem>
                <NavItem><NavLink to="/cas">CAs</NavLink></NavItem>
                <NavItem><NavLink to="/cross-certs">Cross-Certs</NavLink></NavItem>
              </>
            )}
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

function AuthenticatedLayout() {
  const { token, role, clearAuth } = useAuth();
  const navigate = useNavigate();

  if (!token) return <Navigate to="/login" replace />;
  if (!role) return <Spinner />;

  async function handleLogout() {
    await apiLogout();
    clearAuth();
    navigate('/login');
  }

  return (
    <Page
      masthead={<AppHeader onLogout={handleLogout} />}
      sidebar={<AppSidebar role={role} />}
      isManagedSidebar
    >
      <Outlet />
    </Page>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<AuthenticatedLayout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/certs" element={<Certificates />} />
        <Route path="/orders" element={<Orders />} />
        <Route path="/accounts" element={<Accounts />} />
        <Route path="/audit" element={<AuditLog />} />
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
          <RequireRole minRole="ca_ra"><CAs /></RequireRole>
        } />
        <Route path="/cross-certs" element={
          <RequireRole minRole="ca_ra"><CrossCerts /></RequireRole>
        } />
        <Route path="/operators" element={
          <RequireRole minRole="administrator"><Operators /></RequireRole>
        } />
        <Route path="/config" element={
          <RequireRole minRole="administrator"><ServerConfig /></RequireRole>
        } />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
