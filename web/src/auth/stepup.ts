/**
 * Step-up WebAuthn: re-toque na chave de segurança ANTES de usar a chave de
 * assinatura (docs/console-seguranca.md). O servidor guarda a janela (<= 5 min)
 * na sessão e a confere em POST /api/acoes e no registro da chave.
 */
import { finalizarStepUp, iniciarStepUp } from '../api/endpoints';
import { executarAsercao } from './webauthn';

export async function fazerStepUp(): Promise<void> {
  const inicio = await iniciarStepUp();
  const credencial = await executarAsercao(inicio.opcoes);
  await finalizarStepUp(inicio.cerimonia, credencial);
}
