/**
 * Envio de uma ação de agente escolhida no painel: monta o JobPayload com os
 * `params` do formulário, faz step-up, assina no navegador e POST /api/acoes
 * (tudo via executarAcaoAssinada). Fail-closed sem chave de assinatura.
 */
import type { AcaoDisponivel, Agente } from '../api/tipos';
import { serializarJob } from '../auth/canonico';
import { mensagemDeErro, type ContextoAcao, type ResultadoAcao } from './conectar';
import { executarAcaoAssinada, type DependenciasExecucao } from './executar';

const VALIDADE_JOB_MS = 10 * 60 * 1000;

function hexAleatorio(nBytes: number): string {
  const b = new Uint8Array(nBytes);
  globalThis.crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export async function enviarAcaoDoPainel(
  agente: Pick<Agente, 'id'>,
  acao: Pick<AcaoDisponivel, 'nome' | 'origem'>,
  params: Readonly<Record<string, string>>,
  ctx: ContextoAcao,
  deps?: DependenciasExecucao,
  agora: () => Date = () => new Date(),
): Promise<ResultadoAcao> {
  if (acao.origem !== 'agente') {
    return { ok: false, mensagem: 'Esta ação não é de agente.' };
  }
  if (ctx.assinador === null) {
    return { ok: false, mensagem: 'Cadastre a chave de assinatura antes de enviar ações.' };
  }
  try {
    const t0 = agora();
    const bytes = serializarJob({
      v: 1,
      job_id: 'job-' + hexAleatorio(8),
      agent_id: agente.id,
      action: acao.nome,
      ...(Object.keys(params).length > 0 ? { params } : {}),
      issued_at: t0,
      expires_at: new Date(t0.getTime() + VALIDADE_JOB_MS),
      issuer: ctx.operador,
    });
    const r = await executarAcaoAssinada(ctx.assinador, 'job', bytes, deps);
    return { ok: true, mensagem: `Ação ${acao.nome}: job ${r.job ?? ''} ${r.estado}.`.replace('  ', ' ') };
  } catch (e) {
    return { ok: false, mensagem: mensagemDeErro(e) };
  }
}
