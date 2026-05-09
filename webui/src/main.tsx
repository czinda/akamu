import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { AuthProvider } from './auth/AuthContext';
import '@patternfly/react-core/dist/styles/base.css';

// Set VITE_RH_THEME=true to load the Red Hat brand theme overlay on top of PatternFly.
if (import.meta.env.VITE_RH_THEME === 'true') {
  import('redhat-brand-theme/dist/redhat-brand-theme.css');
}

// Set VITE_AKAMU_THEME=true to load the Akamu brand theme (navy chrome + gold accents).
if (import.meta.env.VITE_AKAMU_THEME === 'true') {
  import('./akamu-theme.css');
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter basename="/ui">
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
);
