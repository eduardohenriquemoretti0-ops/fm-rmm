/**
 * Tipos do contrato da API do console (ver docs/console-handoff-agentes.md).
 *
 * Campos de /api/agentes alinhados ao JSON real do T4 (internal/console/agentes.go,
 * `agenteView`). Qualquer campo novo ou renomeado entra aqui — e só aqui.
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
  /**
   * OPCIONAIS — o servidor (T3) ainda NÃO os devolve. Necessários para montar o
   * RemoteGrant: `tecnico` = TechName do operador; `relay_url` = relay configurado
   * no servidor. Sem eles o "Conectar" falha fechado (ver acoes/conectar.ts).
   */
  readonly tecnico?: string;
  readonly relay_url?: string;
}

/** Agente como exibido no grid (somente leitura). */
export interface Agente {
  readonly id: string;
  readonly hostname: string;
  readonly os: string;
  /** Estado de aprovação/ciclo de vida do agente (ex.: aprovado, pendente). */
  readonly status: string;
  readonly grupo: string;
  readonly online: boolean;
  /** Instante RFC 3339 UTC do último contato, ou null se nunca contatou. */
  readonly ultimo_contato: string | null;
}

/** Resposta de POST /api/acoes (202). */
export interface RespostaAcao {
  readonly job?: string;
  readonly sessao?: string;
  readonly estado: string;
}

/** Resposta de POST /api/operador/chave-assinatura (201). */
export interface RespostaChave {
  readonly key_id: string;
}
