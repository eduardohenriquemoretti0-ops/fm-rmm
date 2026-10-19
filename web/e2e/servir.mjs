// Servidor estático de TESTE (fora do repo). Envia a CSP lida literalmente de internal/console/console.go.
import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Caminhos relativos a este arquivo: web/e2e/ -> ../../internal/console/console.go e ../dist
const HERE = dirname(fileURLToPath(import.meta.url));
const GO = join(HERE, '..', '..', 'internal', 'console', 'console.go');
const DIST = join(HERE, '..', 'dist');

// Extrai a CSP: literais "..." do bloco `const contentSecurityPolicy = ...`
const fonte = readFileSync(GO, 'utf8');
const bloco = fonte.slice(fonte.indexOf('const contentSecurityPolicy'), fonte.indexOf('\n\n', fonte.indexOf('const contentSecurityPolicy')));
const pedacos = [...bloco.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
const CSP = pedacos.join('');

const TIPOS = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };

export { CSP };
export function iniciar(porta = 4173) {
  const srv = createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    let arq = join(DIST, url.pathname === '/' ? 'index.html' : url.pathname);
    if (!arq.startsWith(DIST) || !existsSync(arq) || statSync(arq).isDirectory()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('nao encontrado');
    }
    res.writeHead(200, {
      'Content-Type': TIPOS[extname(arq)] ?? 'application/octet-stream',
      'Content-Security-Policy': CSP,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    });
    res.end(readFileSync(arq));
  });
  return new Promise((ok) => srv.listen(porta, '127.0.0.1', () => ok(srv)));
}

if (process.argv[1] && process.argv[1].endsWith('servir.mjs')) {
  await iniciar(4173);
  console.log('CSP_LIDA=' + CSP);
  console.log('servindo em http://127.0.0.1:4173');
}
