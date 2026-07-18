import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';

export type Role = 'administrator' | 'ca_operations' | 'ca_ra' | 'auditor';

export interface AuthState {
  token: string | null;
  role: Role | null;
  operatorName: string | null;
  expiresAt: string | null;
}

interface AuthContextValue extends AuthState {
  setAuth: (state: AuthState) => void;
  clearAuth: () => void;
}

const STORAGE_KEY = 'akamu_auth';

function loadFromStorage(): AuthState {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw) as AuthState;
  } catch {
    // ignore
  }
  return { token: null, role: null, operatorName: null, expiresAt: null };
}

const AuthContext = createContext<AuthContextValue>({
  token: null,
  role: null,
  operatorName: null,
  expiresAt: null,
  setAuth: () => undefined,
  clearAuth: () => undefined,
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [auth, setAuthState] = useState<AuthState>(loadFromStorage);

  const setAuth = useCallback((state: AuthState) => {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    setAuthState(state);
  }, []);

  const clearAuth = useCallback(() => {
    sessionStorage.removeItem(STORAGE_KEY);
    setAuthState({ token: null, role: null, operatorName: null, expiresAt: null });
  }, []);

  // Auto-logout when token expires.
  useEffect(() => {
    if (!auth.expiresAt) return;
    const ms = new Date(auth.expiresAt).getTime() - Date.now();
    if (ms <= 0) {
      clearAuth();
      return;
    }
    const tid = setTimeout(clearAuth, ms);
    return () => clearTimeout(tid);
  }, [auth.expiresAt, clearAuth]);

  const value = useMemo(
    () => ({ ...auth, setAuth, clearAuth }),
    [auth, setAuth, clearAuth],
  );

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  return useContext(AuthContext);
}

// eslint-disable-next-line react-refresh/only-export-components
export function roleRank(role: Role | null): number {
  switch (role) {
    case 'administrator':
      return 4;
    case 'ca_operations':
      return 3;
    case 'ca_ra':
      return 2;
    case 'auditor':
      return 1;
    default:
      return 0;
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function hasRole(current: Role | null, minRole: Role): boolean {
  return roleRank(current) >= roleRank(minRole);
}
