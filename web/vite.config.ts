/// <reference types="vitest/config" />
/**
 * Configuração do Vite do console web do FM-RMM.
 *
 * O build tem de carregar sob a CSP de internal/console/console.go:
 *   default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; ...
 * Por isso o build NÃO pode gerar <script> inline, <style> inline nem atributos
 * style="...". O plugin `cspGuard` reprova o build se algo disso aparecer.
 * Ver web/README.md (seção "Conformidade com a CSP").
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

/** Padrões proibidos no HTML de saída (violam script-src/style-src 'self'). */
const PADROES_HTML_PROIBIDOS: ReadonlyArray<{ nome: string; re: RegExp }> = [
  // <script> sem atributo src (inline)
  { nome: 'script inline', re: /<script\b(?![^>]*\ssrc=)[^>]*>/i },
  // <style> em qualquer lugar
  { nome: '<style> inline', re: /<style\b/i },
  // atributo style="..." em elementos
  { nome: 'atributo style=""', re: /\sstyle\s*=/i },
  // atributos de evento (onclick=, onerror=...) também são inline script
  { nome: 'handler de evento inline', re: /\son[a-z]+\s*=/i },
];

/** Padrões proibidos nos JS de saída (exigiriam unsafe-eval). */
const PADROES_JS_PROIBIDOS: ReadonlyArray<{ nome: string; re: RegExp }> = [
  { nome: 'eval()', re: /(^|[^.\w$])eval\s*\(/ },
  { nome: 'new Function()', re: /new\s+Function\s*\(/ },
];

function listarArquivos(dir: string, ext: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return listarArquivos(p, ext);
    return e.name.endsWith(ext) ? [p] : [];
  });
}

function cspGuard(): Plugin {
  let outDir = 'dist';
  return {
    name: 'fm-rmm-csp-guard',
    apply: 'build',
    enforce: 'post',
    configResolved(config) {
      outDir = resolve(config.root, config.build.outDir);
    },
    closeBundle() {
      const problemas: string[] = [];

      const html = join(outDir, 'index.html');
      if (!existsSync(html)) {
        problemas.push('index.html não foi gerado');
      } else {
        const conteudo = readFileSync(html, 'utf8');
        for (const { nome, re } of PADROES_HTML_PROIBIDOS) {
          if (re.test(conteudo)) problemas.push(`index.html contém ${nome}`);
        }
      }

      for (const arq of listarArquivos(join(outDir, 'assets'), '.js')) {
        const conteudo = readFileSync(arq, 'utf8');
        for (const { nome, re } of PADROES_JS_PROIBIDOS) {
          if (re.test(conteudo)) problemas.push(`${arq} contém ${nome}`);
        }
      }

      if (problemas.length > 0) {
        throw new Error(
          'Build reprovado pela CSP do console (internal/console/console.go):\n - ' +
            problemas.join('\n - '),
        );
      }
      // eslint-disable-next-line no-console
      console.log('[csp-guard] OK: sem script/style inline nem eval no build.');
    },
  };
}

export default defineConfig({
  plugins: [react(), cspGuard()],
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    target: 'es2022',
    sourcemap: false,
    cssCodeSplit: false,
    // o polyfill de modulepreload injeta código; os navegadores-alvo não precisam
    modulePreload: { polyfill: false },
    reportCompressedSize: false,
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.{ts,tsx}'],
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    // Em dev, o Vite injeta CSS via <style> em JS, o que a CSP de produção bloqueia.
    // Para validar CSP use sempre o build servido (ver README).
  },
});
