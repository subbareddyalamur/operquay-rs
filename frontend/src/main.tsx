import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/inter/700.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import './styles/index.css';
import { App } from './App';
import { AuthGate } from './components/auth/SignInPage';
import { installSessionWatch } from './stores/auth';
import KubernetesWorkspace from './workspaces/kubernetes/App.jsx';

const isKubernetesRoute =
  window.location.pathname === '/k8s' || window.location.pathname.startsWith('/k8s/');

if (!isKubernetesRoute) {
  installSessionWatch();
}

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('Root element #root not found');
createRoot(rootEl).render(
  <StrictMode>
    {isKubernetesRoute ? (
      <KubernetesWorkspace />
    ) : (
      <AuthGate>
        <App />
      </AuthGate>
    )}
  </StrictMode>,
);
