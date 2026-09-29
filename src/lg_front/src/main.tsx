import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './App';
import { createSession } from './auth/session';
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
