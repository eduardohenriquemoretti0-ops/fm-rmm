/**
 * Registro de credencial WebAuthn (navigator.credentials.create).
 * Ponte entre o JSON do go-webauthn (base64url) e a API do navegador.
 * Uso: operador PENDENTE, atrás do cert mTLS, sem sessão.
 */
import { finalizarRegistro, iniciarRegistro } from '../api/endpoints';
import type { OpcoesRegistroJSON } from '../api/tipos';
import { base64urlParaBytes, bytesParaBase64url, ErroWebAuthn } from './webauthn';

const TIMEOUT_MAXIMO_MS = 120_000;
const TIMEOUT_PADRAO_MS = 60_000;

export interface CredencialRegistroJSON {
  readonly id: string;
  readonly rawId: string;
  readonly type: 'public-key';
  readonly clientExtensionResults: Record<string, never>;
  readonly response: {
    readonly clientDataJSON: string;
    readonly attestationObject: string;
    readonly transports?: string[];
  };
}

export function paraOpcoesCriacao(json: OpcoesRegistroJSON): PublicKeyCredentialCreationOptions {
  const pk = json.publicKey;
  if (pk.pubKeyCredParams.length === 0) {
    throw new ErroWebAuthn('servidor não informou algoritmos');
  }
  const sel = pk.authenticatorSelection;
  return {
    challenge: base64urlParaBytes(pk.challenge),
    rp: { name: pk.rp.name, ...(pk.rp.id !== undefined ? { id: pk.rp.id } : {}) },
    user: {
      id: base64urlParaBytes(pk.user.id),
      name: pk.user.name,
      displayName: pk.user.displayName,
    },
    pubKeyCredParams: pk.pubKeyCredParams.map((p) => ({ type: p.type, alg: p.alg })),
    timeout: Math.min(pk.timeout ?? TIMEOUT_PADRAO_MS, TIMEOUT_MAXIMO_MS),
    excludeCredentials: (pk.excludeCredentials ?? []).map((c) => ({
      type: 'public-key' as const,
      id: base64urlParaBytes(c.id),
      ...(c.transports !== undefined ? { transports: c.transports as AuthenticatorTransport[] } : {}),
    })),
    // UV obrigatório: o servidor também exige (VerificationRequired). Sem attestation.
    authenticatorSelection: {
      userVerification: sel?.userVerification ?? 'required',
      ...(sel?.authenticatorAttachment !== undefined
        ? { authenticatorAttachment: sel.authenticatorAttachment as AuthenticatorAttachment }
        : {}),
      ...(sel?.residentKey !== undefined
        ? { residentKey: sel.residentKey as ResidentKeyRequirement }
        : {}),
    },
    attestation: 'none',
  };
}

export function serializarRegistro(cred: PublicKeyCredential): CredencialRegistroJSON {
  const resp = cred.response;
  if (!(resp instanceof AuthenticatorAttestationResponse)) {
    throw new ErroWebAuthn('resposta do autenticador não é um registro');
  }
  const transports = typeof resp.getTransports === 'function' ? resp.getTransports() : [];
  return {
    id: cred.id,
    rawId: bytesParaBase64url(cred.rawId),
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: bytesParaBase64url(resp.clientDataJSON),
      attestationObject: bytesParaBase64url(resp.attestationObject),
      ...(transports.length > 0 ? { transports } : {}),
    },
  };
}

/** Executa create() no autenticador com as opções do servidor. */
export async function executarCriacao(json: OpcoesRegistroJSON): Promise<CredencialRegistroJSON> {
  if (typeof window === 'undefined' || !window.isSecureContext) {
    throw new ErroWebAuthn('WebAuthn exige contexto seguro (HTTPS)');
  }
  if (typeof PublicKeyCredential === 'undefined' || !navigator.credentials) {
    throw new ErroWebAuthn('navegador sem suporte a WebAuthn');
  }
  const cred = await navigator.credentials.create({ publicKey: paraOpcoesCriacao(json) });
  if (!(cred instanceof PublicKeyCredential)) {
    throw new ErroWebAuthn('autenticador não devolveu credencial');
  }
  return serializarRegistro(cred);
}

/** Fluxo completo: /api/registro/inicio -> create() -> /api/registro/fim. Devolve o id. */
export async function registrarCredencial(): Promise<string> {
  const inicio = await iniciarRegistro();
  const credencial = await executarCriacao(inicio.opcoes);
  return finalizarRegistro(inicio.cerimonia, credencial);
}
