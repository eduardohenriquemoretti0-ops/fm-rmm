/**
 * Autenticador de assinatura do operador (WebCrypto, Ed25519 NÃO exportável).
 *
 * Lei: docs/console-seguranca.md (§Assinatura ida-e-volta) e
 * docs/console-assinatura-acao.md. O servidor NÃO assina nada: a chave privada
 * nasce e morre no navegador do operador (`extractable:false`). Se o navegador
 * não tem Ed25519 no SubtleCrypto, falha CLARAMENTE — nunca cai para uma lib JS
 * que precise manter/exportar a chave.
 */
import { reserializar, type TipoAcao } from './canonico';

export class ErroAssinatura extends Error {
  constructor(mensagem: string) {
    super(mensagem);
    this.name = 'ErroAssinatura';
  }
}

/** Navegador sem Ed25519 no WebCrypto: o console não pode assinar ações. */
export class ErroEd25519Indisponivel extends ErroAssinatura {
  constructor() {
    super(
      'Este navegador não suporta Ed25519 no WebCrypto. Atualize para Chrome/Edge 137+, ' +
        'Firefox 129+ ou Safari 17+ (ver web/README.md). Assinatura de ações desativada.',
    );
    this.name = 'ErroEd25519Indisponivel';
  }
}

/** h1 anunciado != SHA-256 do payload recebido, ou assinatura não confere na volta. */
export class ErroIntegridade extends ErroAssinatura {
  constructor(mensagem: string) {
    super(mensagem);
    this.name = 'ErroIntegridade';
  }
}

/** Prefixo da prova de posse (internal/console/acoes.go: ProvaChaveContexto). */
export const PROVA_CHAVE_CONTEXTO = 'fmrmm-signing-pub-v1';

const ALGORITMO = 'Ed25519';

/** Cópia tipada como BufferSource aceitável pelo SubtleCrypto. */
function buf(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(b);
}

function subtle(): SubtleCrypto {
  const s = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (s === undefined) throw new ErroAssinatura('WebCrypto indisponível (exige contexto seguro HTTPS).');
  return s;
}

export function bytesParaB64(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return btoa(s);
}

export function b64ParaBytes(t: string): Uint8Array {
  const s = atob(t);
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
  return b;
}

export function bytesParaHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export async function sha256(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest('SHA-256', buf(b)));
}

/** key_id = hex dos 8 primeiros bytes de SHA-256(pub de 32 bytes) (= sign.KeyID do Go). */
export async function keyIdDe(pubRaw: Uint8Array): Promise<string> {
  if (pubRaw.length !== 32) throw new ErroAssinatura('chave pública Ed25519 deve ter 32 bytes');
  return bytesParaHex((await sha256(pubRaw)).subarray(0, 8));
}

/**
 * Feature-detect: o SubtleCrypto sabe gerar Ed25519? (Chrome/Edge antigos
 * lançam NotSupportedError.) Resultado em cache.
 */
let cacheSuporte: Promise<boolean> | null = null;
export function ed25519Disponivel(): Promise<boolean> {
  cacheSuporte ??= (async () => {
    try {
      await subtle().generateKey({ name: ALGORITMO }, false, ['sign', 'verify']);
      return true;
    } catch {
      return false;
    }
  })();
  return cacheSuporte;
}

/** Zera o cache do feature-detect (testes). */
export function _reiniciarDeteccao(): void {
  cacheSuporte = null;
}

/** O que o resto do SPA precisa de um assinador (permite fake nos testes). */
export interface Assinador {
  readonly pubRaw: Uint8Array;
  readonly keyId: string;
  /** Confere h1 contra o SHA-256 dos bytes RECEBIDOS, assina e verifica na volta. */
  assinar(bytes: Uint8Array, h1Hex: string): Promise<Uint8Array>;
  verificar(bytes: Uint8Array, sig: Uint8Array): Promise<boolean>;
}

export class Autenticador implements Assinador {
  private constructor(
    private readonly privada: CryptoKey,
    private readonly publica: CryptoKey,
    readonly pubRaw: Uint8Array,
    readonly keyId: string,
  ) {}

  /** Gera o par com a privada NÃO EXPORTÁVEL. Falha clara sem Ed25519. */
  static async gerarPar(): Promise<CryptoKeyPair> {
    if (!(await ed25519Disponivel())) throw new ErroEd25519Indisponivel();
    return (await subtle().generateKey({ name: ALGORITMO }, false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
  }

  static async gerar(): Promise<Autenticador> {
    return Autenticador.dePar(await Autenticador.gerarPar());
  }

  /**
   * Usa um par já existente (ex.: recuperado do IndexedDB). RECUSA privada
   * exportável, a não ser que `somenteTeste` seja passado (vetor do doc).
   */
  static async dePar(par: CryptoKeyPair, opcoes: { somenteTeste?: true } = {}): Promise<Autenticador> {
    if (par.privateKey.extractable && opcoes.somenteTeste !== true) {
      throw new ErroAssinatura('chave privada exportável recusada');
    }
    if (par.privateKey.algorithm.name !== ALGORITMO) {
      throw new ErroAssinatura('chave não é Ed25519');
    }
    const pubRaw = new Uint8Array(await subtle().exportKey('raw', par.publicKey));
    return new Autenticador(par.privateKey, par.publicKey, pubRaw, await keyIdDe(pubRaw));
  }

  get pubB64(): string {
    return bytesParaB64(this.pubRaw);
  }

  async assinar(bytes: Uint8Array, h1Hex: string): Promise<Uint8Array> {
    // passo 3: recomputa h1' do que RECEBEU e compara com o h1 anunciado
    const h1linha = bytesParaHex(await sha256(bytes));
    if (h1linha !== h1Hex.toLowerCase()) {
      throw new ErroIntegridade('payload divergente do hash anunciado (h1 != h1\'); assinatura abortada');
    }
    // passo 4: assina os bytes canônicos exatos
    const sig = new Uint8Array(await subtle().sign(ALGORITMO, this.privada, buf(bytes)));
    if (sig.length !== 64) throw new ErroAssinatura('assinatura Ed25519 deve ter 64 bytes');
    // passo 5: na volta, a assinatura tem de verificar sobre os MESMOS bytes
    if (!(await this.verificar(bytes, sig))) {
      throw new ErroIntegridade('assinatura não confere na volta; envio abortado');
    }
    return sig;
  }

  verificar(bytes: Uint8Array, sig: Uint8Array): Promise<boolean> {
    return subtle().verify(ALGORITMO, this.publica, buf(sig), buf(bytes));
  }
}

/** Corpo de POST /api/acoes. `payload` e `sig` em base64 PADRÃO dos BYTES. */
export interface AcaoAssinada {
  readonly tipo: TipoAcao;
  readonly payload: string;
  readonly sig: string;
  readonly key_id: string;
}

/**
 * Fluxo completo de assinatura de uma ação (docs/console-seguranca.md):
 * canônico confere -> h1 -> autenticador reconfere h1' e assina -> verifica a
 * volta -> monta o envelope. Qualquer divergência LANÇA (nunca envia).
 */
export async function assinarAcao(
  aut: Assinador,
  tipo: TipoAcao,
  bytes: Uint8Array,
): Promise<AcaoAssinada> {
  // os bytes precisam ser exatamente o que o servidor re-serializaria
  const de = bytesParaHex(bytes);
  const re = bytesParaHex(reserializar(tipo, bytes));
  if (de !== re) throw new ErroIntegridade('payload não canônico; assinatura abortada');

  const h1 = bytesParaHex(await sha256(bytes));
  const sig = await aut.assinar(bytes, h1);
  if (!(await aut.verificar(bytes, sig))) {
    throw new ErroIntegridade('assinatura não confere sobre os bytes canônicos; envio abortado');
  }

  const payload = bytesParaB64(bytes);
  const sigB64 = bytesParaB64(sig);
  // a codificação também tem de fazer ida-e-volta
  if (bytesParaHex(b64ParaBytes(payload)) !== de) {
    throw new ErroIntegridade('base64 do payload não reproduz os bytes');
  }
  return { tipo, payload, sig: sigB64, key_id: aut.keyId };
}

/** Mensagem da prova de posse: "fmrmm-signing-pub-v1\n<operador>\n<pub b64>". */
export function mensagemProvaChave(operadorId: string, pubB64: string): Uint8Array {
  return new TextEncoder().encode(`${PROVA_CHAVE_CONTEXTO}\n${operadorId}\n${pubB64}`);
}

/** Corpo de POST /api/operador/chave-assinatura. */
export interface RegistroChave {
  readonly signing_pub: string;
  readonly prova: string;
}

/** Assina a prova de posse com a própria chave e confere na volta. */
export async function montarRegistroChave(aut: Autenticador, operadorId: string): Promise<RegistroChave> {
  const msg = mensagemProvaChave(operadorId, aut.pubB64);
  const sig = await aut.assinar(msg, bytesParaHex(await sha256(msg)));
  return { signing_pub: aut.pubB64, prova: bytesParaB64(sig) };
}
