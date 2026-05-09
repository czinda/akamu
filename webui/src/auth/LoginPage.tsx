import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  LoginPage as PFLoginPage,
  Alert,
  Tab,
  Tabs,
  TabTitleText,
  TextInput,
  FormGroup,
  Form,
  ActionGroup,
  Button,
} from '@patternfly/react-core';
import { loginGssapi, loginEab } from '../api/session';
import { useAuth } from './AuthContext';

export default function LoginPage() {
  const navigate = useNavigate();
  const { setAuth } = useAuth();
  const [activeTab, setActiveTab] = useState<string | number>(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [kid, setKid] = useState('');
  const [hmacKey, setHmacKey] = useState('');

  async function handleGssapi() {
    setError(null);
    setLoading(true);
    try {
      const data = await loginGssapi();
      setAuth({ token: data.session_token, role: data.role, operatorName: data.operator, expiresAt: data.expires_at });
      navigate('/');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'GSSAPI authentication failed');
    } finally {
      setLoading(false);
    }
  }

  async function handleEab(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const data = await loginEab(kid, hmacKey);
      setAuth({ token: data.session_token, role: data.role, operatorName: data.operator, expiresAt: data.expires_at });
      navigate('/');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'EAB authentication failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <PFLoginPage
      loginTitle="Sign in to Akamu PKI"
      brandImgAlt="Akamu PKI"
    >
      {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
      <Tabs activeKey={activeTab} onSelect={(_e, key) => setActiveTab(key)}>
        <Tab eventKey={0} title={<TabTitleText>Kerberos (GSSAPI)</TabTitleText>}>
          <div style={{ padding: '1rem 0' }}>
            <p style={{ marginBottom: '1rem' }}>
              Click the button below to authenticate with your Kerberos ticket. Your browser will
              automatically negotiate credentials if configured for SPNEGO.
            </p>
            <Button variant="primary" onClick={handleGssapi} isLoading={loading} isDisabled={loading}>
              Sign in with Kerberos
            </Button>
          </div>
        </Tab>
        <Tab eventKey={1} title={<TabTitleText>EAB Key</TabTitleText>}>
          <Form onSubmit={handleEab} style={{ padding: '1rem 0' }}>
            <FormGroup label="Key ID (kid)" isRequired fieldId="eab-kid">
              <TextInput
                id="eab-kid"
                value={kid}
                onChange={(_e, v) => setKid(v)}
                isRequired
                autoComplete="username"
              />
            </FormGroup>
            <FormGroup label="HMAC Key (base64url)" isRequired fieldId="eab-hmac">
              <TextInput
                id="eab-hmac"
                type="password"
                value={hmacKey}
                onChange={(_e, v) => setHmacKey(v)}
                isRequired
                autoComplete="current-password"
              />
            </FormGroup>
            <ActionGroup>
              <Button type="submit" variant="primary" isLoading={loading} isDisabled={loading || !kid || !hmacKey}>
                Sign in
              </Button>
            </ActionGroup>
          </Form>
        </Tab>
      </Tabs>
    </PFLoginPage>
  );
}
