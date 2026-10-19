/**
 * Orquestra uma ação do operador: step-up WebAuthn -> assinatura no navegador
 * (com integridade ida-e-volta) -> POST /api/acoes. Dependências injetáveis para
 * teste; o padrão usa as reais.
 */
import { enviarAcao } from '../api/endpoints';
import type { RespostaAcao } from '../api/tipos';
import { assinarAcao, type Assinador } from '../auth/assinatura';
import type { TipoAcao } from '../auth/canonico';
import { fazerStepUp } from '../auth/stepup';

export interface DependenciasExecucao {
  readonly stepUp: () => Promise<void>;
  readonly enviar: typeof enviarAcao;
}

const REAIS: DependenciasExecucao = { stepUp: fazerStepUp, enviar: enviarAcao };

export async function executarAcaoAssinada(
  aut: Assinador,
  tipo: TipoAcao,
  bytesCanonicos: Uint8Array,
  deps: DependenciasExecucao = REAIS,
): Promise<RespostaAcao> {
  await deps.stepUp(); // antes de usar a chave
  const acao = await assinarAcao(aut, tipo, bytesCanonicos);
  return deps.enviar(acao);
}
