import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './App';
import { createSession } from './auth/session';
// Self-hosted fonts (the CSP allows font-src 'self' only): Latin subsets of Inter
// 400/500/600/700 and JetBrains Mono 400/500, emitted as files by the build.
import '@fontsource/inter/latin-400.css';
import '@fontsource/inter/latin-ext-400.css';
import '@fontsource/inter/latin-500.css';
import '@fontsource/inter/latin-ext-500.css';
import '@fontsource/inter/latin-600.css';
import '@fontsource/inter/latin-ext-600.css';
import '@fontsource/inter/latin-700.css';
import '@fontsource/inter/latin-ext-700.css';
import '@fontsource/jetbrains-mono/latin-400.css';
import '@fontsource/jetbrains-mono/latin-ext-400.css';
import '@fontsource/jetbrains-mono/latin-500.css';
import '@fontsource/jetbrains-mono/latin-ext-500.css';
import './theme/tokens.css';
import './index.css';
import { createQueryClient } from './queryClient';

const root = document.getElementById('root');
if (!root) throw new Error('missing #root');

let session;
try {
  session = createSession();
} catch (err) {
  // Invalid /config.js: show the problem instead of a blank page.
  root.textContent = `LG-SOTF could not start: ${err instanceof Error ? err.message : String(err)}`;
  throw err;
}

createRoot(root).render(
  <StrictMode>
    <App session={session} queryClient={createQueryClient()} />
  </StrictMode>,
);
