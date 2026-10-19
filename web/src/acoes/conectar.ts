/**
 * Botão "Conectar" (RemoteGrant) e ação de job de exemplo ("info"), ligados ao
 * autenticador de assinatura. Monta o objeto, serializa em bytes canônicos,
 * faz step-up, assina e envia a POST /api/acoes.
 *
 * Fail-closed: sem chave neste navegador, sem `tecnico`/`relay_url` vindos do
 * servidor ou sem Ed25519, NADA é enviado e a mensagem diz o que falta.
 */
import type { Agente } from '../api/tipos';
import type { Assinador } from '../auth/assinatura';
import { serializarGrant, serializarJob } from '../auth/canonico';
import { executarAcaoAssinada, type DependenciasExecucao } from './executar';

export interface ContextoAcao {
  readonly operador: string;
  /** TechName do operador (RemoteGrant.technician). Vem do servidor. */
  readonly tecnico?: string | undefined;
  /** Relay configurado no servidor (RemoteGrant.relay_url). O operador não escolhe. */
  readonly relayUrl?: string | undefined;
  /** Assinador do operador (null = chave ainda não cadastrada neste navegador). */
  readonly assinador: Assinador | null;
}

export type ResultadoAcao =
  | { readonly ok: true; readonly mensagem: string }
  | { readonly ok: false; readonly mensagem: string };

const VALIDADE_GRANT_MS = 10 * 60 * 1000;
const VALIDADE_JOB_MS = 10 * 60 * 1000;

function hexAleatorio(nBytes: number): string {
  const b = new Uint8Array(nBytes);
  globalThis.crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function base64urlAleatorio(nBytes: number): string {
  const b = new Uint8Array(nBytes);
  globalThis.crypto.getRandomValues(b);
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const MENSAGENS_ERRO: Readonly<Record<string, string>> = {
  step_up_necessario: 'Confirme com a chave de segurança (step-up) e tente de novo.',
  operador_sem_chave_de_assinatura: 'Seu operador ainda não tem chave de assinatura registrada.',
  assinatura_invalida: 'Assinatura recusada: a chave deste navegador não é a registrada.',
  payload_nao_canonico: 'O servidor recusou a forma do payload (canonicalização divergente).',
  emissor_ou_nonce_invalido: 'Emissor ou identificador da ação inválido.',
  agente_nao_encontrado: 'Agente não encontrado ou sem permissão.',
  agente_indisponivel: 'Agente não está aprovado/disponível.',
  nonce_repetido: 'Ação repetida (identificador já usado).',
  acao_expirada: 'A ação expirou. Tente de novo (verifique o relógio do computador).',
  acao_emitida_no_futuro: 'Relógio do computador adiantado. Ajuste a hora.',
  acao_fora_do_catalogo: 'Ação fora do catálogo para este sistema operacional.',
  relay_invalido: 'Relay inválido para esta sessão.',
  validade_acima_do_maximo: 'Validade acima do máximo permitido.',
};

export function mensagemDeErro(erro: unknown): string {
  const e = erro as { name?: string; message?: string; codigo?: string; status?: number };
  if (e?.name === 'ErroApi') {
    if (e.codigo !== undefined && MENSAGENS_ERRO[e.codigo] !== undefined) {
      return MENSAGENS_ERRO[e.codigo] as string;
    }
    return e.message ?? 'Falha ao enviar a ação.';
  }
  if (
    e?.name === 'ErroEd25519Indisponivel' ||
    e?.name === 'ErroIntegridade' ||
    e?.name === 'ErroAssinatura' ||
    e?.name === 'ErroCanonico'
  ) {
    return e.message ?? 'Falha na assinatura.';
  }
  if (e?.name === 'NotAllowedError') return 'Operação cancelada ou tempo esgotado no autenticador.';
  return 'Não foi possível concluir a ação.';
}

/** Abre sessão remota (grant `view`, engine `screenshot`) assinada pelo operador. */
export async function conectarAgente(
  agente: Agente,
  ctx: ContextoAcao,
  deps?: DependenciasExecucao,
  agora: () => Date = () => new Date(),
): Promise<ResultadoAcao> {
  if (ctx.assinador === null) {
    return { ok: false, mensagem: 'Cadastre a chave de assinatura antes de conectar.' };
  }
  if (!ctx.tecnico || !ctx.relayUrl) {
    return {
      ok: false,
      mensagem:
        'O servidor não informou técnico/relay na sessão (pendência do backend). Nada foi enviado.',
    };
  }
  try {
    const t0 = agora();
    const bytes = serializarGrant({
      v: 1,
      session_id: 'ses-' + hexAleatorio(8),
      agent_id: agente.id,
      technician: ctx.tecnico,
      mode: 'view',
      engine: 'screenshot',
      relay_url: ctx.relayUrl,
      relay_token: base64urlAleatorio(32),
      issued_at: t0,
      expires_at: new Date(t0.getTime() + VALIDADE_GRANT_MS),
      issuer: ctx.operador,
    });
    const r = await executarAcaoAssinada(ctx.assinador, 'grant', bytes, deps);
    return { ok: true, mensagem: `Sessão ${r.sessao ?? ''} ${r.estado}.`.replace('  ', ' ') };
  } catch (e) {
    return { ok: false, mensagem: mensagemDeErro(e) };
  }
}

/** Job de exemplo: ação `info` (catálogo) no agente, assinada pelo operador. */
export async function enviarJobInfo(
  agente: Agente,
  ctx: ContextoAcao,
  deps?: DependenciasExecucao,
  agora: () => Date = () => new Date(),
): Promise<ResultadoAcao> {
  if (ctx.assinador === null) {
    return { ok: false, mensagem: 'Cadastre a chave de assinatura antes de enviar ações.' };
  }
  try {
    const t0 = agora();
    const bytes = serializarJob({
      v: 1,
      job_id: 'job-' + hexAleatorio(8),
      agent_id: agente.id,
      action: 'info',
      issued_at: t0,
      expires_at: new Date(t0.getTime() + VALIDADE_JOB_MS),
      issuer: ctx.operador,
    });
    const r = await executarAcaoAssinada(ctx.assinador, 'job', bytes, deps);
    return { ok: true, mensagem: `Job ${r.job ?? ''} ${r.estado}.`.replace('  ', ' ') };
  } catch (e) {
    return { ok: false, mensagem: mensagemDeErro(e) };
  }
}
