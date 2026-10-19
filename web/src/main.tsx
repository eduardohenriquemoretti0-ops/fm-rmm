import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles.css';

const raiz = document.getElementById('raiz');
if (raiz === null) {
  throw new Error('Elemento #raiz ausente no index.html');
}

createRoot(raiz).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
