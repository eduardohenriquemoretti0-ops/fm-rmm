/**
 * Tipos do contrato da API do console (ver docs/console-handoff-agentes.md).
 *
 * Os campos de /api/agents ainda não são definitivos: o T4 (backend) fixa o JSON.
 * Qualquer campo novo ou renomeado entra aqui — e só aqui.
 */

/** Resposta de POST /api/login/fim: o token de sessão vai só no cookie HttpOnly. */
export interface RespostaLoginFim {
  readonly operador: string;
  /** Token CSRF da sessão. Guardado SOMENTE em memória (nunca em localStorage). */
  readonly csrf: string;
}

/** Resposta de POST /api/login/inicio: chave da cerimônia + opções WebAuthn. */
export interface RespostaLoginInicio {
  /** Chave da cerimônia; volta no header X-FMRMM-Cerimonia do /fim. */
  readonly cerimonia: string;
  /** Opções no formato go-webauthn: { publicKey: { challenge, allowCredentials, ... } }. */
  readonly opcoes: OpcoesAsercaoJSON;
}

/** Forma JSON das opções de asserção (base64url nos campos binários). */
export interface OpcoesAsercaoJSON {
  readonly publicKey: {
    readonly challenge: string;
    readonly timeout?: number;
    readonly rpId?: string;
    readonly allowCredentials?: ReadonlyArray<{
      readonly type: 'public-key';
      readonly id: string;
      readonly transports?: ReadonlyArray<string>;
    }>;
    readonly userVerification?: 'required' | 'preferred' | 'discouraged';
  };
}

/** Resposta de GET /api/sessao. */
export interface RespostaSessao {
  readonly operador: string;
  readonly nome: string;
  readonly csrf: string;
}

/** Agente como exibido no grid (somente leitura). */
export interface Agente {
  readonly id: string;
  readonly hostname: string;
  readonly os: string;
  readonly online: boolean;
  /** Instante ISO 8601 do último contato, ou null se nunca contatou. */
  readonly ultimo_contato: string | null;
}
