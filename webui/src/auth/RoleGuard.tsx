import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth, hasRole, Role } from './AuthContext';

interface RoleGuardProps {
  minRole: Role;
  children: React.ReactElement;
  fallback?: React.ReactElement;
}

export default function RoleGuard({ minRole, children, fallback }: RoleGuardProps) {
  const { role } = useAuth();
  if (!hasRole(role, minRole)) {
    return fallback ?? <Navigate to="/" replace />;
  }
  return children;
}
