/**
 * Cliente HTTP do console.
 *
 * Regras (docs/console-seguranca.md — lei):
 * - o token de sessão é só o cookie HttpOnly: este módulo NUNCA lê ou grava cookie;
 * - `credentials: 'include'` para o navegador enviar o cookie e o cert mTLS;
 * - o token CSRF fica SOMENTE em memória (variável do módulo), nunca em
 *   localStorage/sessionStorage/cookie;
 * - nenhuma mensagem de erro carrega o corpo da resposta do servidor (sem info-leak).
 */

/** Header anti-CSRF exigido nas rotas de escrita (internal/console/acesso.go). */
export const CABECALHO_CSRF = 'X-FMRMM-CSRF';

/** Header que carrega a chave da cerimônia WebAuthn (internal/console/rotas.go). */
export const CABECALHO_CERIMONIA = 'X-FMRMM-Cerimonia';

/** Erro de API com status HTTP e mensagem segura para exibir ao operador. */
export class ErroApi extends Error {
  readonly status: number;
  /**
   * Código `erro` do servidor (ex.: `step_up_necessario`), só se casar com
   * `^[a-z_]{1,48}$`. É um identificador de máquina; NUNCA é exibido cru.
   */
  readonly codigo: string | undefined;

  constructor(status: number, mensagem: string, codigo?: string) {
    super(mensagem);
    this.name = 'ErroApi';
    this.status = status;
    this.codigo = codigo;
  }
}

let csrfEmMemoria: string | null = null;

/** Define (ou limpa, com null) o token CSRF da sessão atual. Só memória. */
export function definirCsrf(token: string | null): void {
  csrfEmMemoria = token;
}

/** Retorna o token CSRF em memória, ou null se não há sessão. */
export function obterCsrf(): string | null {
  return csrfEmMemoria;
}

// Base da API: vazio = mesma origem (produção, servido pelo backend).
const BASE_API: string = (import.meta.env.VITE_API_BASE as string | undefined) ?? '';

function mensagemPorStatus(status: number): string {
  if (status === 401) return 'Sessão ausente ou expirada. Entre novamente.';
  if (status === 403) return 'Operação não permitida para este operador.';
  if (status === 404) return 'Recurso não encontrado.';
  if (status === 429) return 'Muitas tentativas. Aguarde antes de tentar de novo.';
  if (status >= 500) return 'Erro interno do servidor.';
  return `Falha na requisição (HTTP ${status}).`;
}

/** Extrai só o identificador `erro` do corpo de falha (sem ecoar texto do servidor). */
async function codigoDeErro(resp: Response): Promise<string | undefined> {
  try {
    const j = (await resp.json()) as { erro?: unknown };
    return typeof j.erro === 'string' && /^[a-z_]{1,48}$/.test(j.erro) ? j.erro : undefined;
  } catch {
    return undefined;
  }
}

export interface OpcoesChamada {
  readonly metodo?: 'GET' | 'POST';
  /** Corpo JSON (ou, para o /fim do WebAuthn, o objeto da credencial). */
  readonly corpo?: unknown;
  /** Chave da cerimônia, enviada em X-FMRMM-Cerimonia. */
  readonly cerimonia?: string;
  readonly signal?: AbortSignal;
}

/**
 * Chama a API do console e devolve o JSON já parseado.
 * Lança ErroApi em qualquer falha (rede, HTTP não-2xx, corpo não-JSON).
 * O chamador deve validar a forma do retorno (ver endpoints.ts).
 */
export async function chamarApi(caminho: string, op: OpcoesChamada = {}): Promise<unknown> {
  if (!caminho.startsWith('/api/')) {
    throw new ErroApi(0, 'Caminho de API inválido.');
  }
  const metodo = op.metodo ?? 'GET';
  const cabecalhos = new Headers({ Accept: 'application/json' });
  if (op.corpo !== undefined) cabecalhos.set('Content-Type', 'application/json');
  if (op.cerimonia) cabecalhos.set(CABECALHO_CERIMONIA, op.cerimonia);
  if (metodo !== 'GET' && csrfEmMemoria !== null) {
    cabecalhos.set(CABECALHO_CSRF, csrfEmMemoria);
  }

  let resp: Response;
  try {
    const init: RequestInit = {
      method: metodo,
      headers: cabecalhos,
      credentials: 'include',
      mode: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      ...(op.corpo !== undefined ? { body: JSON.stringify(op.corpo) } : {}),
      ...(op.signal !== undefined ? { signal: op.signal } : {}),
    };
    resp = await fetch(BASE_API + caminho, init);
  } catch (erro) {
    // AbortError é cancelamento deliberado, não falha de rede.
    if (erro instanceof DOMException && erro.name === 'AbortError') throw erro;
    throw new ErroApi(
      0,
      'Falha de conexão com o servidor. Verifique o certificado de operador instalado.',
    );
  }

  if (!resp.ok) {
    throw new ErroApi(resp.status, mensagemPorStatus(resp.status), await codigoDeErro(resp));
  }
  const tipo = resp.headers.get('content-type') ?? '';
  if (!tipo.includes('application/json')) {
    throw new ErroApi(resp.status, 'Resposta inesperada do servidor.');
  }
  try {
    return (await resp.json()) as unknown;
  } catch {
    throw new ErroApi(resp.status, 'Resposta inválida do servidor.');
  }
}
