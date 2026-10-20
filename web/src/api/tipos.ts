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
  readonly vulnerabilidades: VulnCompacto;
  readonly updates: UpdatesResumo;
  readonly saude: SaudeResumo;
}

/** Resumo compacto de CVEs por agente (escaneado=false => nunca escaneado). */
export interface VulnCompacto {
  readonly escaneado: boolean;
  readonly escaneado_em: string | null;
  readonly total: number;
  /** Chaves como o servidor manda: CRITICAL, HIGH, MEDIUM, LOW, DESCONHECIDA. */
  readonly por_severidade: Readonly<Record<string, number>>;
}

/** null = desconhecido. */
export interface UpdatesResumo {
  readonly pendentes: number | null;
  readonly reinicio_pendente: boolean | null;
}

/** null = desconhecido. */
export interface SaudeResumo {
  readonly estavel: boolean | null;
  readonly eventos: number | null;
}

/** Achado de CVE (GET /api/agentes/{id}/vulnerabilidades). */
export interface ItemVuln {
  readonly cve_id: string;
  readonly pacote: string;
  readonly versao: string;
  readonly severidade: string;
  readonly pontuacao: number | null;
  readonly fixed_version: string;
}

/** Item de alto risco que nenhuma fonte soube cruzar com CVE. */
export interface NaoAvaliado {
  readonly pacote: string;
  readonly versao: string;
  readonly motivo: string;
}

/** Resposta de GET /api/agentes/{id}/vulnerabilidades. */
export interface ResumoVulnerabilidades {
  readonly escaneado: boolean;
  readonly escaneado_em: string | null;
  readonly fonte: string;
  readonly total: number;
  readonly por_severidade: Readonly<Record<string, number>>;
  readonly vulnerabilidades: ReadonlyArray<ItemVuln>;
  readonly nao_avaliados_alto_risco: ReadonlyArray<NaoAvaliado>;
}

/** Opções de registro WebAuthn (go-webauthn CredentialCreation). */
export interface OpcoesRegistroJSON {
  readonly publicKey: {
    readonly challenge: string;
    readonly rp: { readonly id?: string; readonly name: string };
    readonly user: { readonly id: string; readonly name: string; readonly displayName: string };
    readonly pubKeyCredParams: ReadonlyArray<{ readonly type: 'public-key'; readonly alg: number }>;
    readonly timeout?: number;
    readonly excludeCredentials?: ReadonlyArray<{
      readonly type: 'public-key';
      readonly id: string;
      readonly transports?: ReadonlyArray<string>;
    }>;
    readonly authenticatorSelection?: {
      readonly authenticatorAttachment?: string;
      readonly residentKey?: string;
      readonly requireResidentKey?: boolean;
      readonly userVerification?: 'required' | 'preferred' | 'discouraged';
    };
    readonly attestation?: string;
  };
}

/** Resposta de POST /api/registro/inicio. */
export interface RespostaRegistroInicio {
  readonly cerimonia: string;
  readonly opcoes: OpcoesRegistroJSON;
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

/** Tipos de campo que a UI sabe montar (internal/console/listas.go). */
export type TipoParam =
  | 'texto'
  | 'lista'
  | 'item_catalogo_software'
  | 'script_biblioteca_id'
  | 'script_biblioteca_versao'
  | 'confirmacao_destrutiva';

/** Param de uma ação de GET /api/acoes-disponiveis. */
export interface ParamAcao {
  readonly nome: string;
  readonly rotulo: string;
  readonly obrigatorio: boolean;
  readonly tipo: TipoParam;
  readonly valores_por_so?: Readonly<Record<string, ReadonlyArray<string>>>;
  /** Só em confirmacao_destrutiva: ex. "WIPE-{agent_id}". */
  readonly formato?: string;
}

/** Ação de escrita de GET /api/acoes-disponiveis. */
export interface AcaoDisponivel {
  readonly nome: string;
  readonly rotulo: string;
  readonly origem: 'agente' | 'bmc';
  readonly rota: string;
  readonly destrutiva: boolean;
  readonly exige_step_up: boolean;
  readonly so?: ReadonlyArray<string>;
  readonly params: ReadonlyArray<ParamAcao>;
}

/** Item de GET /api/catalogo-software (sem pkg_id/hash). */
export interface ItemSoftware {
  readonly id: string;
  readonly nome: string;
  readonly gerenciador: string;
}

/** Item de GET /api/biblioteca-scripts (sem corpo). */
export interface ScriptBiblioteca {
  readonly id: string;
  readonly nome: string;
  readonly versao: string;
  readonly interprete: string;
}

/** Corpo de POST /api/bmc/power|status. usuario/senha só existem durante a chamada. */
export interface CorpoBmc {
  readonly host: string;
  readonly porta: number;
  readonly system_id: string;
  readonly acao: string;
  readonly usuario: string;
  readonly senha: string;
}

/** Resposta (sem segredo) de /api/bmc/*. */
export interface RespostaBmc {
  readonly resultado: string;
  readonly host?: string;
  readonly acao?: string;
  readonly estado?: { readonly power_state: string; readonly health?: string; readonly modelo?: string };
}
