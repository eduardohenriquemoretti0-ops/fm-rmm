/**
 * Serialização CANÔNICA das ações assinadas (JobPayload / RemoteGrant).
 *
 * Lei: docs/console-assinatura-acao.md. Os bytes têm de ser IDÊNTICOS ao
 * `json.Marshal` da struct Go (proto.JobPayload / proto.RemoteGrant): o servidor
 * recusa (`payload_nao_canonico`) qualquer divergência. Aqui NUNCA se usa
 * JSON.stringify de objeto: a ordem dos campos é fixa e escrita à mão.
 *
 * Regras (espelham encoding/json do Go):
 * - compacto, UTF-8; campos na ordem da struct; `params` com chaves em ordem
 *   de bytes UTF-8; `params`/`media_secret` omitidos quando vazios;
 * - instantes RFC 3339 UTC com `Z`, truncados para segundos;
 * - escapes: `"` `\` `\b` `\f` `\n` `\r` `\t`, demais controles `\u00xx`, e
 *   `<` `>` `&` U+2028 U+2029 como `<` `>` `&` ` ` ` `
 *   (minúsculas); `/` literal; surrogate solto vira U+FFFD (como o Go faz com
 *   UTF-8 inválido).
 */

export class ErroCanonico extends Error {
  constructor(mensagem: string) {
    super(mensagem);
    this.name = 'ErroCanonico';
  }
}

export interface JobPayload {
  readonly v: 1;
  readonly job_id: string;
  readonly agent_id: string;
  readonly action: string;
  /** Vazio/omitido => campo OMITIDO no JSON. */
  readonly params?: Readonly<Record<string, string>>;
  readonly issued_at: Date;
  readonly expires_at: Date;
  readonly issuer: string;
}

export interface RemoteGrant {
  readonly v: 1;
  readonly session_id: string;
  readonly agent_id: string;
  readonly technician: string;
  readonly mode: 'view' | 'control';
  readonly engine: 'screenshot' | 'rustdesk';
  /** Vazio/omitido => campo OMITIDO no JSON. */
  readonly media_secret?: string;
  readonly relay_url: string;
  readonly relay_token: string;
  readonly issued_at: Date;
  readonly expires_at: Date;
  readonly issuer: string;
}

export type TipoAcao = 'job' | 'grant';

/** Validade máxima (docs): job 24 h, grant 30 min. */
const MAX_JOB_MS = 24 * 3600 * 1000;
const MAX_GRANT_MS = 30 * 60 * 1000;
const RE_NONCE = /^[A-Za-z0-9_-]{8,64}$/;
const RE_INSTANTE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const HEX = '0123456789abcdef';

function escU(cu: number): string {
  return '\\u' + HEX[(cu >> 12) & 15] + HEX[(cu >> 8) & 15] + HEX[(cu >> 4) & 15] + HEX[cu & 15];
}

/** String JSON exatamente como o encoding/json do Go (com escapeHTML ligado). */
export function jsonString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    if (cp >= 0xd800 && cp <= 0xdfff) {
      out += '\\ufffd'; // surrogate solto: Go emite � para UTF-8 inválido
      continue;
    }
    switch (ch) {
      case '"': out += '\\"'; continue;
      case '\\': out += '\\\\'; continue;
      case '\b': out += '\\b'; continue;
      case '\f': out += '\\f'; continue;
      case '\n': out += '\\n'; continue;
      case '\r': out += '\\r'; continue;
      case '\t': out += '\\t'; continue;
      case '<': case '>': case '&': out += escU(cp); continue;
      case ' ': case ' ': out += escU(cp); continue;
      default:
    }
    out += cp < 0x20 ? escU(cp) : ch;
  }
  return out + '"';
}

/** Instante RFC 3339 UTC, `Z`, truncado para segundos. */
export function formatarInstante(d: Date): string {
  const ms = d.getTime();
  if (!Number.isFinite(ms)) throw new ErroCanonico('instante inválido');
  const trunc = new Date(Math.floor(ms / 1000) * 1000);
  const ano = trunc.getUTCFullYear();
  if (ano < 1 || ano > 9999) throw new ErroCanonico('instante fora de 0001..9999');
  return trunc.toISOString().replace(/\.000Z$/, 'Z');
}

/** Compara strings por bytes UTF-8 (= ordem de code points), como o Go ordena chaves. */
function compararBytes(a: string, b: string): number {
  const ca = Array.from(a, (c) => c.codePointAt(0) as number);
  const cb = Array.from(b, (c) => c.codePointAt(0) as number);
  const n = Math.min(ca.length, cb.length);
  for (let i = 0; i < n; i++) {
    const d = (ca[i] as number) - (cb[i] as number);
    if (d !== 0) return d;
  }
  return ca.length - cb.length;
}

function validarJanela(emitido: Date, expira: Date, maxMs: number): void {
  formatarInstante(emitido);
  formatarInstante(expira);
  const dur = Math.floor(expira.getTime() / 1000) * 1000 - Math.floor(emitido.getTime() / 1000) * 1000;
  if (dur <= 0) throw new ErroCanonico('expires_at deve ser posterior a issued_at');
  if (dur > maxMs) throw new ErroCanonico('validade acima do máximo');
}

function campo(nome: string, valor: string): string {
  return `${jsonString(nome)}:${jsonString(valor)}`;
}

/** Bytes canônicos do JobPayload (idênticos ao json.Marshal do Go). */
export function serializarJob(j: JobPayload): Uint8Array {
  if (j.v !== 1) throw new ErroCanonico('v deve ser 1');
  if (!RE_NONCE.test(j.job_id)) throw new ErroCanonico('job_id fora de ^[A-Za-z0-9_-]{8,64}$');
  validarJanela(j.issued_at, j.expires_at, MAX_JOB_MS);
  const partes = [
    '"v":1',
    campo('job_id', j.job_id),
    campo('agent_id', j.agent_id),
    campo('action', j.action),
  ];
  const chaves = Object.keys(j.params ?? {});
  if (chaves.length > 0) {
    chaves.sort(compararBytes);
    const p = chaves.map((k) => `${jsonString(k)}:${jsonString((j.params as Record<string, string>)[k] as string)}`);
    partes.push(`"params":{${p.join(',')}}`);
  }
  partes.push(
    campo('issued_at', formatarInstante(j.issued_at)),
    campo('expires_at', formatarInstante(j.expires_at)),
    campo('issuer', j.issuer),
  );
  return new TextEncoder().encode(`{${partes.join(',')}}`);
}

/** Bytes canônicos do RemoteGrant (idênticos ao json.Marshal do Go). */
export function serializarGrant(g: RemoteGrant): Uint8Array {
  if (g.v !== 1) throw new ErroCanonico('v deve ser 1');
  if (!RE_NONCE.test(g.session_id)) {
    throw new ErroCanonico('session_id fora de ^[A-Za-z0-9_-]{8,64}$');
  }
  if (g.mode !== 'view' && g.mode !== 'control') throw new ErroCanonico('mode inválido');
  if (g.engine !== 'screenshot' && g.engine !== 'rustdesk') {
    throw new ErroCanonico('engine inválido');
  }
  if (g.relay_token.length < 32) throw new ErroCanonico('relay_token curto (mín. 32)');
  if (g.engine === 'rustdesk' && !g.media_secret) {
    throw new ErroCanonico('media_secret obrigatório com rustdesk');
  }
  validarJanela(g.issued_at, g.expires_at, MAX_GRANT_MS);
  const partes = [
    '"v":1',
    campo('session_id', g.session_id),
    campo('agent_id', g.agent_id),
    campo('technician', g.technician),
    campo('mode', g.mode),
    campo('engine', g.engine),
  ];
  if (g.media_secret) partes.push(campo('media_secret', g.media_secret));
  partes.push(
    campo('relay_url', g.relay_url),
    campo('relay_token', g.relay_token),
    campo('issued_at', formatarInstante(g.issued_at)),
    campo('expires_at', formatarInstante(g.expires_at)),
    campo('issuer', g.issuer),
  );
  return new TextEncoder().encode(`{${partes.join(',')}}`);
}

type Reg = Record<string, unknown>;

function exigirChaves(o: Reg, esperadas: readonly string[]): void {
  for (const k of Object.keys(o)) {
    if (!esperadas.includes(k)) throw new ErroCanonico(`campo desconhecido: ${k}`);
  }
}
function txt(o: Reg, k: string): string {
  const v = o[k];
  if (typeof v !== 'string') throw new ErroCanonico(`campo ${k} ausente ou não-texto`);
  return v;
}
function inst(o: Reg, k: string): Date {
  const v = txt(o, k);
  if (!RE_INSTANTE.test(v)) throw new ErroCanonico(`${k} não é RFC 3339 UTC sem fração`);
  return new Date(v);
}

/**
 * Decodifica os bytes (campos desconhecidos recusados) e re-serializa. O
 * resultado DEVE ser igual aos bytes de entrada: é a mesma checagem que o
 * servidor faz (`payload_nao_canonico`), feita antes de assinar.
 */
export function reserializar(tipo: TipoAcao, bytes: Uint8Array): Uint8Array {
  let obj: unknown;
  try {
    obj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new ErroCanonico('payload não é JSON UTF-8 válido');
  }
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    throw new ErroCanonico('payload não é objeto');
  }
  const o = obj as Reg;
  if (o.v !== 1) throw new ErroCanonico('v deve ser 1');
  if (tipo === 'job') {
    exigirChaves(o, ['v', 'job_id', 'agent_id', 'action', 'params', 'issued_at', 'expires_at', 'issuer']);
    let params: Record<string, string> | undefined;
    if (o.params !== undefined) {
      if (typeof o.params !== 'object' || o.params === null || Array.isArray(o.params)) {
        throw new ErroCanonico('params inválido');
      }
      params = {};
      for (const [k, v] of Object.entries(o.params)) {
        if (typeof v !== 'string') throw new ErroCanonico('params deve ser string->string');
        params[k] = v;
      }
    }
    return serializarJob({
      v: 1,
      job_id: txt(o, 'job_id'),
      agent_id: txt(o, 'agent_id'),
      action: txt(o, 'action'),
      ...(params !== undefined ? { params } : {}),
      issued_at: inst(o, 'issued_at'),
      expires_at: inst(o, 'expires_at'),
      issuer: txt(o, 'issuer'),
    });
  }
  exigirChaves(o, [
    'v', 'session_id', 'agent_id', 'technician', 'mode', 'engine', 'media_secret',
    'relay_url', 'relay_token', 'issued_at', 'expires_at', 'issuer',
  ]);
  const ms = o.media_secret === undefined ? undefined : txt(o, 'media_secret');
  return serializarGrant({
    v: 1,
    session_id: txt(o, 'session_id'),
    agent_id: txt(o, 'agent_id'),
    technician: txt(o, 'technician'),
    mode: txt(o, 'mode') as RemoteGrant['mode'],
    engine: txt(o, 'engine') as RemoteGrant['engine'],
    ...(ms !== undefined ? { media_secret: ms } : {}),
    relay_url: txt(o, 'relay_url'),
    relay_token: txt(o, 'relay_token'),
    issued_at: inst(o, 'issued_at'),
    expires_at: inst(o, 'expires_at'),
    issuer: txt(o, 'issuer'),
  });
}
