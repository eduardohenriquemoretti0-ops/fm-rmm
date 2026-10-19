// Teste de navegador: SPA sob a CSP real do console + WebAuthn com autenticador virtual.
// Uso: (cd web && npm run build) && CHROMIUM_EXE=/caminho/chrome-headless-shell node web/e2e/csp-webauthn.mjs
// Requer: npm i -D playwright-core (não é dependência de produção).
// Teste de navegador do SPA sob a CSP real do console (servidor de teste fora do repo).
import { chromium } from 'playwright-core';
import { iniciar, CSP as CSP_ATUAL } from './servir.mjs';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

// Chromium: defina CHROMIUM_EXE (ex.: o binário do Playwright ou do sistema)
const EXE = process.env.CHROMIUM_EXE;
if (!EXE) { console.error('Defina CHROMIUM_EXE com o caminho do Chromium headless.'); process.exit(2); }
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const resultados = [];
const check = (nome, ok, extra = '') => { resultados.push({ nome, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${nome}${extra ? '  -> ' + extra : ''}`); };

const srv = await iniciar(4173);
console.log('CSP usada (de internal/console/console.go):', CSP_ATUAL);
const browser = await chromium.launch({ executablePath: EXE, args: ['--no-sandbox'] });

async function novaPagina() {
  const ctx = await browser.newContext({ baseURL: 'http://localhost:4173' });
  const page = await ctx.newPage();
  const erros = [];
  page.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') erros.push(m.text()); });
  page.on('pageerror', (e) => erros.push('pageerror: ' + e.message));
  // Captura violações de CSP reportadas pelo próprio navegador
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' | ' + e.blockedURI));
  });
  return { ctx, page, erros };
}
const cspDe = (page) => page.evaluate(() => window.__csp);

// ---------- Cenário 1: sem sessão -> tela de login, nenhuma violação ----------
{
  const { ctx, page, erros } = await novaPagina();
  await page.route('**/api/sessao', (r) => r.fulfill({ status: 401, contentType: 'application/json', body: '{"erro":"x"}' }));
  await page.goto('/');
  await page.getByRole('button', { name: 'Entrar com chave de segurança' }).waitFor({ timeout: 10000 });
  check('C1 sem sessão mostra tela de login', true);
  const csp = await cspDe(page);
  check('C1 zero violações de CSP', csp.length === 0, csp.join(' ; ') || 'nenhuma');
  const esperados401 = erros.filter((e) => e.includes('status of 401'));
  const reais = erros.filter((e) => !e.includes('status of 401'));
  check('C1 zero erros de console (exceto o 401 esperado de /api/sessao sem sessão)', reais.length === 0 && esperados401.length >= 1, reais.join(' | ') || `401 esperados=${esperados401.length}`);
  await ctx.close();
}

// ---------- Cenário 2: grid com dado hostil + logout com CSRF ----------
{
  const { ctx, page, erros } = await novaPagina();
  let headerLogout = null, headerAgentes = null;
  await page.route('**/api/sessao', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ operador: 'op-a', nome: 'Ana', csrf: 'csrf-123' }) }));
  await page.route('**/api/agents', async (r) => {
    headerAgentes = r.request().headers()['x-fmrmm-csrf'] ?? null;
    await r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([
      { id: 'ag-01', hostname: 'SRV-Jundiai', os: 'Windows 10', online: true, ultimo_contato: '2026-10-18T12:00:00Z' },
      { id: '<img src=x onerror=alert(1)>', hostname: '<svg onload=alert(2)>', os: '"><script>alert(3)</script>', online: false, ultimo_contato: null },
    ]) });
  });
  await page.route('**/api/logout', async (r) => {
    headerLogout = r.request().headers()['x-fmrmm-csrf'] ?? null;
    await r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
  });
  await page.goto('/');
  await page.getByRole('heading', { name: 'Agentes' }).waitFor({ timeout: 10000 });
  const linhas = await page.locator('tbody tr').count();
  check('C2 grid renderiza 2 linhas', linhas === 2, `linhas=${linhas}`);
  const textoHostil = await page.locator('tbody tr').nth(1).innerText();
  check('C2 dado hostil aparece como texto literal', textoHostil.includes('<svg onload=alert(2)>') && textoHostil.includes('<img src=x onerror=alert(1)>'));
  const injetado = await page.evaluate(() => document.querySelectorAll('img[src="x"], svg[onload], script:not([src]):not([type])').length);
  check('C2 nenhum elemento injetado pelo dado do agente', injetado === 0, `injetados=${injetado}`);
  check('C2 GET /api/agents não envia CSRF', headerAgentes === null, `header=${headerAgentes}`);
  // Busca
  await page.getByRole('searchbox', { name: 'Buscar agentes' }).fill('jundiai');
  check('C2 busca filtra para 1 linha', (await page.locator('tbody tr').count()) === 1);
  await page.getByRole('searchbox', { name: 'Buscar agentes' }).fill('');
  // Botão Conectar = stub (não faz chamada de rede de ação)
  let chamouAcoes = false;
  await page.route('**/api/acoes', (r) => { chamouAcoes = true; r.fulfill({ status: 500, body: '' }); });
  await page.locator('tbody tr').first().getByRole('button', { name: 'Conectar' }).click();
  await page.getByText('Conectar ainda não está disponível').waitFor();
  check('C2 Conectar é stub: mostra aviso e não chama /api/acoes', !chamouAcoes);
  // Logout com CSRF
  await page.getByRole('button', { name: 'Sair' }).click();
  await page.getByRole('button', { name: 'Entrar com chave de segurança' }).waitFor();
  check('C2 logout envia X-FMRMM-CSRF e volta ao login', headerLogout === 'csrf-123', `header=${headerLogout}`);
  const armazenou = await page.evaluate(() => [localStorage.length, sessionStorage.length]);
  check('C2 nada gravado em localStorage/sessionStorage', armazenou[0] === 0 && armazenou[1] === 0, JSON.stringify(armazenou));
  const csp = await cspDe(page);
  check('C2 zero violações de CSP', csp.length === 0, csp.join(' ; ') || 'nenhuma');
  check('C2 zero erros de console', erros.length === 0, erros.join(' | ') || 'nenhum');
  await ctx.close();
}

// ---------- Cenário 3: login WebAuthn ponta a ponta (autenticador virtual CDP) ----------
{
  const { ctx, page, erros } = await novaPagina();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true } });
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const credId = randomBytes(32);
  await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: {
    credentialId: Buffer.from(credId).toString('base64'), isResidentCredential: false, rpId: 'localhost',
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    signCount: 0 } });

  const desafio = randomBytes(32);
  let cabecalhoCerimonia = null, corpoFim = null, sessaoAtiva = false;
  await page.route('**/api/sessao', (r) => sessaoAtiva
    ? r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ operador: 'op-a', nome: 'Ana', csrf: 'csrf-login' }) })
    : r.fulfill({ status: 401, contentType: 'application/json', body: '{"erro":"x"}' }));
  await page.route('**/api/login/inicio', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
    cerimonia: 'chave-cerimonia-123',
    opcoes: { publicKey: { challenge: b64u(desafio), timeout: 60000, rpId: 'localhost',
      allowCredentials: [{ type: 'public-key', id: b64u(credId) }], userVerification: 'required' } } }) }));
  await page.route('**/api/login/fim', async (r) => {
    cabecalhoCerimonia = r.request().headers()['x-fmrmm-cerimonia'] ?? null;
    corpoFim = JSON.parse(r.request().postData() ?? 'null');
    sessaoAtiva = true;
    await r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ operador: 'op-a', csrf: 'csrf-login' }) });
  });
  await page.route('**/api/agents', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));

  await page.goto('/');
  await page.getByRole('button', { name: 'Entrar com chave de segurança' }).click();
  await page.getByRole('heading', { name: 'Agentes' }).waitFor({ timeout: 15000 });
  check('C3 login WebAuthn conclui e entra no console', true);
  check('C3 /fim recebe X-FMRMM-Cerimonia do /inicio', cabecalhoCerimonia === 'chave-cerimonia-123', `header=${cabecalhoCerimonia}`);
  const cdj = corpoFim ? JSON.parse(Buffer.from(corpoFim.response.clientDataJSON, 'base64url').toString('utf8')) : {};
  check('C3 clientDataJSON é webauthn.get com o challenge do servidor', cdj.type === 'webauthn.get' && cdj.challenge === b64u(desafio) && cdj.origin === 'http://localhost:4173', `type=${cdj.type} origin=${cdj.origin}`);
  check('C3 corpo do /fim tem id/rawId/type/response completos', !!(corpoFim && corpoFim.id && corpoFim.rawId && corpoFim.type === 'public-key' && corpoFim.response.authenticatorData && corpoFim.response.signature));
  check('C3 CSRF veio só em memória (nada em storage)', (await page.evaluate(() => localStorage.length + sessionStorage.length)) === 0);
  const csp = await cspDe(page);
  check('C3 zero violações de CSP durante a cerimônia', csp.length === 0, csp.join(' ; ') || 'nenhuma');
  const reaisC3 = erros.filter((e) => !e.includes('status of 401'));
  check('C3 zero erros de console (exceto o 401 esperado de /api/sessao antes do login)', reaisC3.length === 0, reaisC3.join(' | ') || 'nenhum');
  await ctx.close();
}

// ---------- Cenário 4: fail-closed (servidor sem allowCredentials) ----------
{
  const { ctx, page } = await novaPagina();
  await page.route('**/api/sessao', (r) => r.fulfill({ status: 401, contentType: 'application/json', body: '{"erro":"x"}' }));
  await page.route('**/api/login/inicio', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ cerimonia: 'k', opcoes: { publicKey: { challenge: b64u(randomBytes(16)) } } }) }));
  let fimChamado = false;
  await page.route('**/api/login/fim', (r) => { fimChamado = true; r.fulfill({ status: 500, body: '' }); });
  await page.goto('/');
  await page.getByRole('button', { name: 'Entrar com chave de segurança' }).click();
  await page.getByRole('alert').waitFor({ timeout: 10000 });
  check('C4 sem allowCredentials: erro na tela e /fim NÃO é chamado', !fimChamado, await page.getByRole('alert').innerText());
  await ctx.close();
}

// ---------- Controle negativo: inline script sob a MESMA CSP tem de ser bloqueado ----------
{
  const { ctx, page } = await novaPagina();
  
  await page.route('**/controle.html', (r) => r.fulfill({
    status: 200, contentType: 'text/html',
    headers: { 'Content-Security-Policy': CSP_ATUAL },
    body: '<!doctype html><html><body><div id="x">antes</div><script>document.getElementById("x").textContent="EXECUTOU";</script></body></html>' }));
  await page.goto('/controle.html');
  await page.waitForTimeout(500);
  const exec = await page.evaluate(() => document.getElementById('x').textContent);
  const csp = await cspDe(page);
  check('C5 controle: inline script é BLOQUEADO pela CSP (teste tem poder)', exec === 'antes' && csp.some((c) => c.startsWith('script-src')), `texto=${exec} violacoes=${csp.join(';')}`);
  await ctx.close();
}

await browser.close();
srv.close();
const falhas = resultados.filter((r) => !r.ok).length;
console.log(`\nRESUMO: ${resultados.length - falhas}/${resultados.length} PASS, ${falhas} FAIL`);
process.exit(falhas ? 1 : 0);
