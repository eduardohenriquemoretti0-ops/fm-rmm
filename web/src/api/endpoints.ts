/**
 * Funções de alto nível para cada endpoint do console, com validação da forma
 * do JSON recebido (não confiamos cegamente no servidor).
 */
import { chamarApi, ErroApi } from './cliente';
import type {
  Agente,
  OpcoesAsercaoJSON,
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

function ehAgente(x: unknown): x is Agente {
  return (
    ehRegistro(x) &&
    ehTexto(x.id) &&
    ehTexto(x.hostname) &&
    ehTexto(x.os) &&
    ehTexto(x.status) &&
    ehTexto(x.grupo) &&
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
 * Step-up WebAuthn (re-toque). ATENÇÃO: o backend tem Autenticador.IniciaStepUp /
 * FinalizaStepUp, mas ainda NÃO expõe rota HTTP (rotas.go). Os caminhos abaixo são
 * a convenção espelhada de /api/login/*; ajustar aqui quando o backend publicar.
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
