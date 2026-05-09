import React from 'react';
import { Routes, Route, Navigate, NavLink, useNavigate } from 'react-router-dom';
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
import { useAuth, hasRole } from './auth/AuthContext';
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

function RequireAuth({ children }: { children: React.ReactElement }) {
  const { token } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  return children;
}

function AppHeader() {
  const { role, operatorName, clearAuth } = useAuth();
  const navigate = useNavigate();

  async function handleLogout() {
    await apiLogout();
    clearAuth();
    navigate('/login');
  }

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
            <Button variant="link" onClick={handleLogout}>Logout</Button>
          </FlexItem>
        </Flex>
      </MastheadContent>
    </Masthead>
  );
}

function AppSidebar({ role }: { role: string | null }) {
  const isAtLeastCaRa = hasRole(role as Parameters<typeof hasRole>[0], 'ca_ra');
  const isAdmin = hasRole(role as Parameters<typeof hasRole>[0], 'administrator');

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
  const { token, role } = useAuth();

  if (!token) return <Navigate to="/login" replace />;
  if (!role) return <Spinner />;

  return (
    <Page masthead={<AppHeader />} sidebar={<AppSidebar role={role} />} isManagedSidebar>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/certs" element={<Certificates />} />
        <Route path="/orders" element={<Orders />} />
        <Route path="/accounts" element={<Accounts />} />
        <Route path="/audit" element={<AuditLog />} />
        {hasRole(role, 'ca_ra') && (
          <>
            <Route path="/eab" element={<EabKeys />} />
            <Route path="/delegations" element={<Delegations />} />
            <Route path="/profiles" element={<Profiles />} />
            <Route path="/cas" element={<CAs />} />
            <Route path="/cross-certs" element={<CrossCerts />} />
          </>
        )}
        {hasRole(role, 'administrator') && (
          <>
            <Route path="/operators" element={<Operators />} />
            <Route path="/config" element={<ServerConfig />} />
          </>
        )}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Page>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <RequireAuth>
            <AuthenticatedLayout />
          </RequireAuth>
        }
      />
    </Routes>
  );
}
