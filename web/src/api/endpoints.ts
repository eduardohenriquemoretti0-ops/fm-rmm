/**
 * Funções de alto nível para cada endpoint do console, com validação da forma
 * do JSON recebido (não confiamos cegamente no servidor).
 */
import { chamarApi, ErroApi } from './cliente';
import type {
  Agente,
  OpcoesAsercaoJSON,
  RespostaLoginFim,
  RespostaLoginInicio,
  RespostaSessao,
} from './tipos';

/**
 * Caminho da lista de agentes. A spec do handoff (T4) usa `/api/agents`
 * (docs/console-handoff-agentes.md). Mudar aqui se o T4 fixar outro nome.
 */
export const CAMINHO_AGENTES = '/api/agents';

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
  return ehRegistro(x) && ehTexto(x.operador) && ehTexto(x.nome) && ehTexto(x.csrf);
}

function ehAgente(x: unknown): x is Agente {
  return (
    ehRegistro(x) &&
    ehTexto(x.id) &&
    ehTexto(x.hostname) &&
    ehTexto(x.os) &&
    typeof x.online === 'boolean' &&
    (x.ultimo_contato === null || ehTexto(x.ultimo_contato))
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

/** GET /api/agents — lista de agentes já filtrada por RBAC no servidor. */
export async function listarAgentes(signal?: AbortSignal): Promise<Agente[]> {
  const r = await chamarApi(CAMINHO_AGENTES, signal ? { signal } : {});
  if (!Array.isArray(r) || !r.every(ehAgente)) throw formaInvalida();
  return r;
}
