/**
 * Funções de alto nível para cada endpoint do console, com validação da forma
 * do JSON recebido (não confiamos cegamente no servidor).
 */
import { chamarApi, ErroApi } from './cliente';
import type {
  Agente,
  ItemVuln,
  NaoAvaliado,
  OpcoesAsercaoJSON,
  OpcoesRegistroJSON,
  RespostaRegistroInicio,
  ResumoVulnerabilidades,
  SaudeResumo,
  UpdatesResumo,
  VulnCompacto,
  RespostaLoginFim,
  RespostaAcao,
  RespostaChave,
  RespostaLoginInicio,
  RespostaSessao,
} from './tipos';
import type { AcaoAssinada, RegistroChave } from '../auth/assinatura';

/** Caminho da lista de agentes (T4: internal/console/rotas.go). */
export const CAMINHO_AGENTES = '/api/agentes';

type Registro = Record<string, unknown>;

function ehRegistro(x: unknown): x is Registro {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function ehTexto(x: unknown): x is string {
  return typeof x === 'string';
}

function formaInvalida(): ErroApi {
  return new ErroApi(0, 'Resposta inesperada do servidor.');
}

function ehOpcoesAsercao(x: unknown): x is OpcoesAsercaoJSON {
  if (!ehRegistro(x) || !ehRegistro(x.publicKey)) return false;
  return ehTexto(x.publicKey.challenge);
}

function ehRespostaSessao(x: unknown): x is RespostaSessao {
  return (
    ehRegistro(x) &&
    ehTexto(x.operador) &&
    ehTexto(x.nome) &&
    ehTexto(x.csrf) &&
    (x.tecnico === undefined || ehTexto(x.tecnico)) &&
    (x.relay_url === undefined || ehTexto(x.relay_url))
  );
}

function ehNumeroOuNulo(x: unknown): x is number | null {
  return x === null || (typeof x === 'number' && Number.isFinite(x));
}

function ehBoolOuNulo(x: unknown): x is boolean | null {
  return x === null || typeof x === 'boolean';
}

function ehMapaContagem(x: unknown): x is Record<string, number> {
  return (
    ehRegistro(x) && Object.values(x).every((v) => typeof v === 'number' && Number.isFinite(v))
  );
}

export function ehVulnCompacto(x: unknown): x is VulnCompacto {
  return (
    ehRegistro(x) &&
    typeof x.escaneado === 'boolean' &&
    (x.escaneado_em === null || ehTexto(x.escaneado_em)) &&
    typeof x.total === 'number' &&
    ehMapaContagem(x.por_severidade)
  );
}

export function ehUpdatesResumo(x: unknown): x is UpdatesResumo {
  return ehRegistro(x) && ehNumeroOuNulo(x.pendentes) && ehBoolOuNulo(x.reinicio_pendente);
}

export function ehSaudeResumo(x: unknown): x is SaudeResumo {
  return ehRegistro(x) && ehBoolOuNulo(x.estavel) && ehNumeroOuNulo(x.eventos);
}

export function ehAgente(x: unknown): x is Agente {
  return (
    ehRegistro(x) &&
    ehTexto(x.id) &&
    ehTexto(x.hostname) &&
    ehTexto(x.os) &&
    ehTexto(x.status) &&
    ehTexto(x.grupo) &&
    typeof x.online === 'boolean' &&
    (x.ultimo_contato === null || ehTexto(x.ultimo_contato)) &&
    ehVulnCompacto(x.vulnerabilidades) &&
    ehUpdatesResumo(x.updates) &&
    ehSaudeResumo(x.saude)
  );
}

/** POST /api/login/inicio — pede a cerimônia de login (exige cert mTLS). */
export async function iniciarLogin(): Promise<RespostaLoginInicio> {
  const r = await chamarApi('/api/login/inicio', { metodo: 'POST' });
  if (!ehRegistro(r) || !ehTexto(r.cerimonia) || !ehOpcoesAsercao(r.opcoes)) {
    throw formaInvalida();
  }
  return { cerimonia: r.cerimonia, opcoes: r.opcoes };
}

/**
 * POST /api/login/fim — envia a credencial WebAuthn assinada. O servidor seta o
 * cookie de sessão HttpOnly e devolve só {operador, csrf}.
 */
export async function finalizarLogin(
  cerimonia: string,
  credencial: unknown,
): Promise<RespostaLoginFim> {
  const r = await chamarApi('/api/login/fim', {
    metodo: 'POST',
    cerimonia,
    corpo: credencial,
  });
  if (!ehRegistro(r) || !ehTexto(r.operador) || !ehTexto(r.csrf)) {
    throw formaInvalida();
  }
  return { operador: r.operador, csrf: r.csrf };
}

/** GET /api/sessao — operador atual e token CSRF. Lança ErroApi 401 sem sessão. */
export async function lerSessao(): Promise<RespostaSessao> {
  const r = await chamarApi('/api/sessao');
  if (!ehRespostaSessao(r)) throw formaInvalida();
  return r;
}

/** POST /api/logout — revoga a sessão no servidor (exige CSRF). */
export async function sair(): Promise<void> {
  await chamarApi('/api/logout', { metodo: 'POST' });
}

/** GET /api/agentes — `{agentes:[...]}` já filtrado por RBAC no servidor. */
export async function listarAgentes(signal?: AbortSignal): Promise<Agente[]> {
  const r = await chamarApi(CAMINHO_AGENTES, signal ? { signal } : {});
  if (!ehRegistro(r) || !Array.isArray(r.agentes) || !r.agentes.every(ehAgente)) {
    throw formaInvalida();
  }
  return r.agentes;
}

/**
 * POST /api/acoes — envia a ação JÁ ASSINADA ({tipo,payload,sig,key_id}). O
 * payload é o base64 dos BYTES canônicos (nunca o objeto). 202 = enfileirada.
 */
export async function enviarAcao(acao: AcaoAssinada): Promise<RespostaAcao> {
  const r = await chamarApi('/api/acoes', { metodo: 'POST', corpo: acao });
  if (!ehRegistro(r) || !ehTexto(r.estado)) throw formaInvalida();
  return {
    estado: r.estado,
    ...(ehTexto(r.job) ? { job: r.job } : {}),
    ...(ehTexto(r.sessao) ? { sessao: r.sessao } : {}),
  };
}

/** POST /api/operador/chave-assinatura — registra a pública + prova de posse. */
export async function registrarChaveAssinatura(corpo: RegistroChave): Promise<RespostaChave> {
  const r = await chamarApi('/api/operador/chave-assinatura', { metodo: 'POST', corpo });
  if (!ehRegistro(r) || !ehTexto(r.key_id)) throw formaInvalida();
  return { key_id: r.key_id };
}

/**
 * Step-up WebAuthn (re-toque): rotas publicadas e funcionando no backend
 * (internal/console/rotas.go), espelhando /api/login/*.
 */
export const CAMINHO_STEPUP_INICIO = '/api/stepup/inicio';
export const CAMINHO_STEPUP_FIM = '/api/stepup/fim';

export async function iniciarStepUp(): Promise<RespostaLoginInicio> {
  const r = await chamarApi(CAMINHO_STEPUP_INICIO, { metodo: 'POST' });
  if (!ehRegistro(r) || !ehTexto(r.cerimonia) || !ehOpcoesAsercao(r.opcoes)) {
    throw formaInvalida();
  }
  return { cerimonia: r.cerimonia, opcoes: r.opcoes };
}

export async function finalizarStepUp(cerimonia: string, credencial: unknown): Promise<void> {
  await chamarApi(CAMINHO_STEPUP_FIM, { metodo: 'POST', cerimonia, corpo: credencial });
}

function ehItemVuln(x: unknown): x is ItemVuln {
  return (
    ehRegistro(x) &&
    ehTexto(x.cve_id) &&
    ehTexto(x.pacote) &&
    ehTexto(x.versao) &&
    ehTexto(x.severidade) &&
    (x.pontuacao === undefined || ehNumeroOuNulo(x.pontuacao)) &&
    ehTexto(x.fixed_version)
  );
}

function ehNaoAvaliado(x: unknown): x is NaoAvaliado {
  return ehRegistro(x) && ehTexto(x.pacote) && ehTexto(x.versao) && ehTexto(x.motivo);
}

/** Valida e normaliza o resumo de CVE (pontuacao ausente vira null). */
export function lerResumoVulns(r: unknown): ResumoVulnerabilidades {
  if (
    !ehRegistro(r) ||
    typeof r.escaneado !== 'boolean' ||
    !(r.escaneado_em === null || ehTexto(r.escaneado_em)) ||
    !ehTexto(r.fonte) ||
    typeof r.total !== 'number' ||
    !ehMapaContagem(r.por_severidade) ||
    !Array.isArray(r.vulnerabilidades) ||
    !r.vulnerabilidades.every(ehItemVuln) ||
    !Array.isArray(r.nao_avaliados_alto_risco) ||
    !r.nao_avaliados_alto_risco.every(ehNaoAvaliado)
  ) {
    throw formaInvalida();
  }
  return {
    escaneado: r.escaneado,
    escaneado_em: r.escaneado_em,
    fonte: r.fonte,
    total: r.total,
    por_severidade: r.por_severidade,
    vulnerabilidades: (r.vulnerabilidades as ItemVuln[]).map((v) => ({
      ...v,
      pontuacao: typeof v.pontuacao === 'number' ? v.pontuacao : null,
    })),
    nao_avaliados_alto_risco: r.nao_avaliados_alto_risco,
  };
}

/** GET /api/agentes/{id}/vulnerabilidades — resumo de CVEs (lê o banco). */
export async function lerVulnerabilidades(
  id: string,
  signal?: AbortSignal,
): Promise<ResumoVulnerabilidades> {
  const r = await chamarApi(
    `/api/agentes/${encodeURIComponent(id)}/vulnerabilidades`,
    signal ? { signal } : {},
  );
  return lerResumoVulns(r);
}

function ehOpcoesRegistro(x: unknown): x is OpcoesRegistroJSON {
  if (!ehRegistro(x) || !ehRegistro(x.publicKey)) return false;
  const pk = x.publicKey;
  return (
    ehTexto(pk.challenge) &&
    ehRegistro(pk.rp) &&
    ehTexto(pk.rp.name) &&
    ehRegistro(pk.user) &&
    ehTexto(pk.user.id) &&
    ehTexto(pk.user.name) &&
    ehTexto(pk.user.displayName) &&
    Array.isArray(pk.pubKeyCredParams)
  );
}

/** POST /api/registro/inicio — só cert; operador precisa estar pendente. */
export async function iniciarRegistro(): Promise<RespostaRegistroInicio> {
  const r = await chamarApi('/api/registro/inicio', { metodo: 'POST' });
  if (!ehRegistro(r) || !ehTexto(r.cerimonia) || !ehOpcoesRegistro(r.opcoes)) {
    throw formaInvalida();
  }
  return { cerimonia: r.cerimonia, opcoes: r.opcoes };
}

/** POST /api/registro/fim — envia a credencial criada; devolve o id (201). */
export async function finalizarRegistro(
  cerimonia: string,
  credencial: unknown,
): Promise<string> {
  const r = await chamarApi('/api/registro/fim', {
    metodo: 'POST',
    cerimonia,
    corpo: credencial,
  });
  if (!ehRegistro(r) || !ehTexto(r.credencial)) throw formaInvalida();
  return r.credencial;
}
