/**
 * Ponte entre o JSON do backend (go-webauthn, base64url) e a API do navegador
 * (navigator.credentials.get, ArrayBuffer).
 *
 * Só o login (asserção) está aqui. O autenticador WebCrypto de assinatura de
 * ações é o T7 e NÃO pertence a este módulo.
 */
import type { OpcoesAsercaoJSON } from '../api/tipos';

/** Teto de timeout da cerimônia no cliente (ms), independente do que o servidor mandar. */
const TIMEOUT_MAXIMO_MS = 120_000;
const TIMEOUT_PADRAO_MS = 60_000;

const RE_BASE64URL = /^[A-Za-z0-9_-]*$/;

/** Credencial de asserção serializada para o JSON do /api/login/fim. */
export interface CredencialAssercaoJSON {
  readonly id: string;
  readonly rawId: string;
  readonly type: 'public-key';
  readonly clientExtensionResults: Record<string, never>;
  readonly response: {
    readonly clientDataJSON: string;
    readonly authenticatorData: string;
    readonly signature: string;
    readonly userHandle: string | null;
  };
}

/** Erro de formato/entrada inválida. Mensagem segura para log, sem dado sensível. */
export class ErroWebAuthn extends Error {
  constructor(mensagem: string) {
    super(mensagem);
    this.name = 'ErroWebAuthn';
  }
}

/** Decodifica base64url (sem padding) em bytes. Lança ErroWebAuthn se inválido. */
export function base64urlParaBytes(texto: string): Uint8Array<ArrayBuffer> {
  if (!RE_BASE64URL.test(texto) || texto.length % 4 === 1) {
    throw new ErroWebAuthn('base64url inválido');
  }
  const padding = '='.repeat((4 - (texto.length % 4)) % 4);
  let binario: string;
  try {
    binario = atob(texto.replace(/-/g, '+').replace(/_/g, '/') + padding);
  } catch {
    throw new ErroWebAuthn('base64url inválido');
  }
  const bytes = new Uint8Array(binario.length);
  for (let i = 0; i < binario.length; i++) {
    bytes[i] = binario.charCodeAt(i);
  }
  return bytes;
}

/** Codifica bytes em base64url sem padding. */
export function bytesParaBase64url(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binario = '';
  for (let i = 0; i < u8.length; i++) {
    binario += String.fromCharCode(u8[i] as number);
  }
  return btoa(binario).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Converte as opções do servidor em PublicKeyCredentialRequestOptions.
 * Fail-closed: sem allowCredentials o login é recusado (o operador precisa ter
 * ao menos uma chave registrada, e o servidor deve dizer qual).
 */
export function paraOpcoesRequisicao(
  json: OpcoesAsercaoJSON,
): PublicKeyCredentialRequestOptions {
  const pk = json.publicKey;
  const permitidas = pk.allowCredentials ?? [];
  if (permitidas.length === 0) {
    throw new ErroWebAuthn('servidor não informou credenciais permitidas');
  }
  const timeout = Math.min(pk.timeout ?? TIMEOUT_PADRAO_MS, TIMEOUT_MAXIMO_MS);
  return {
    challenge: base64urlParaBytes(pk.challenge),
    timeout,
    ...(pk.rpId !== undefined ? { rpId: pk.rpId } : {}),
    allowCredentials: permitidas.map((c) => ({
      type: 'public-key' as const,
      id: base64urlParaBytes(c.id),
      ...(c.transports !== undefined
        ? { transports: c.transports as AuthenticatorTransport[] }
        : {}),
    })),
    userVerification: pk.userVerification ?? 'required',
  };
}

/** Serializa a credencial devolvida pelo navegador para o JSON do /fim. */
export function serializarAsercao(cred: PublicKeyCredential): CredencialAssercaoJSON {
  const resp = cred.response;
  if (!(resp instanceof AuthenticatorAssertionResponse)) {
    throw new ErroWebAuthn('resposta do autenticador não é uma asserção');
  }
  return {
    id: cred.id,
    rawId: bytesParaBase64url(cred.rawId),
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: bytesParaBase64url(resp.clientDataJSON),
      authenticatorData: bytesParaBase64url(resp.authenticatorData),
      signature: bytesParaBase64url(resp.signature),
      userHandle: resp.userHandle ? bytesParaBase64url(resp.userHandle) : null,
    },
  };
}

/**
 * Executa a cerimônia de login no autenticador (chave de segurança/passkey).
 * Lança ErroWebAuthn para entrada inválida ou DOMException para o que o
 * autenticador recusou/cancelou (ex.: NotAllowedError).
 */
export async function executarAsercao(
  json: OpcoesAsercaoJSON,
): Promise<CredencialAssercaoJSON> {
  if (typeof window === 'undefined' || !window.isSecureContext) {
    throw new ErroWebAuthn('WebAuthn exige contexto seguro (HTTPS)');
  }
  if (typeof PublicKeyCredential === 'undefined' || !navigator.credentials) {
    throw new ErroWebAuthn('navegador sem suporte a WebAuthn');
  }
  const opcoes = paraOpcoesRequisicao(json);
  const cred = await navigator.credentials.get({ publicKey: opcoes });
  if (!(cred instanceof PublicKeyCredential)) {
    throw new ErroWebAuthn('autenticador não devolveu credencial');
  }
  return serializarAsercao(cred);
}

/** Mensagem em português, segura para a tela, para qualquer erro da cerimônia. */
export function mensagemErroWebAuthn(erro: unknown): string {
  if (erro instanceof DOMException) {
    if (erro.name === 'NotAllowedError') {
      return 'Operação cancelada ou tempo esgotado no autenticador.';
    }
    if (erro.name === 'SecurityError') {
      return 'Origem não autorizada para WebAuthn. Acesse pelo endereço oficial do console.';
    }
  }
  if (erro instanceof ErroWebAuthn) {
    return 'Não foi possível concluir a verificação no autenticador.';
  }
  return 'Não foi possível concluir o login. Tente novamente.';
}
