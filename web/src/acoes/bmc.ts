/**
 * Controle de energia por BMC/Redfish. A credencial do BMC é digitada NA HORA:
 *  - nunca vai para localStorage/sessionStorage/IndexedDB/cookie;
 *  - nunca é logada nem ecoada em mensagem (o resultado só traz códigos);
 *  - sai do estado do formulário ANTES do envio (ver `aposEnvio`), então nem
 *    uma falha de rede a mantém na memória do componente.
 */
import { chamarBmc } from '../api/endpoints';
import type { CorpoBmc, RespostaBmc } from '../api/tipos';
import { fazerStepUp } from '../auth/stepup';
import { mensagemDeErro } from './conectar';

export interface FormBmc {
  readonly host: string;
  readonly porta: string;
  readonly system_id: string;
  readonly acao: string;
  readonly usuario: string;
  readonly senha: string;
}

export const FORM_BMC_VAZIO: FormBmc = {
  host: '',
  porta: '',
  system_id: '',
  acao: '',
  usuario: '',
  senha: '',
};

/** Estado do formulário depois do envio: credencial apagada, resto mantido. */
export function aposEnvio(f: FormBmc): FormBmc {
  return { ...f, usuario: '', senha: '' };
}

const RE_HOST = /^[A-Za-z0-9._:-]{1,253}$/;
const LIMITE_CREDENCIAL = 256;

export type ResultadoValidacao =
  | { readonly ok: true; readonly corpo: CorpoBmc }
  | { readonly ok: false; readonly erro: string };

export function validarFormBmc(f: FormBmc, acoesPermitidas: ReadonlyArray<string>): ResultadoValidacao {
  const host = f.host.trim();
  if (!RE_HOST.test(host)) return { ok: false, erro: 'Informe o host ou IP do BMC.' };
  let porta = 443;
  if (f.porta.trim() !== '') {
    if (!/^\d{1,5}$/.test(f.porta.trim())) return { ok: false, erro: 'Porta inválida.' };
    porta = Number(f.porta.trim());
    if (porta < 1 || porta > 65535) return { ok: false, erro: 'Porta inválida.' };
  }
  if (!acoesPermitidas.includes(f.acao)) return { ok: false, erro: 'Escolha a ação de energia.' };
  if (f.usuario === '' || f.senha === '') return { ok: false, erro: 'Informe usuário e senha do BMC.' };
  if (f.usuario.length > LIMITE_CREDENCIAL || f.senha.length > LIMITE_CREDENCIAL) {
    return { ok: false, erro: 'Credencial longa demais.' };
  }
  return {
    ok: true,
    corpo: {
      host,
      porta,
      system_id: f.system_id.trim(),
      acao: f.acao,
      usuario: f.usuario,
      senha: f.senha,
    },
  };
}

export interface DependenciasBmc {
  readonly stepUp: () => Promise<void>;
  readonly chamar: typeof chamarBmc;
}

const REAIS: DependenciasBmc = { stepUp: fazerStepUp, chamar: chamarBmc };

const MENSAGENS_BMC: Readonly<Record<string, string>> = {
  ok: 'BMC executou a ação.',
  bmc_credencial_recusada: 'O BMC recusou a credencial informada.',
  destino_nao_permitido: 'Destino do BMC não permitido.',
  bmc_inacessivel: 'BMC inacessível (verifique host/porta).',
  bmc_resposta_invalida: 'Resposta inválida do BMC.',
  sem_permissao_bmc: 'Seu operador não tem permissão de BMC.',
  credencial_bmc_ausente: 'Credencial do BMC ausente.',
  acao_invalida: 'Ação de energia inválida.',
  system_id_invalido: 'system_id inválido.',
  host_invalido: 'Host do BMC inválido.',
  falha_de_auditoria: 'Falha de auditoria: a ação pode ter sido executada. Verifique o BMC.',
};

export function mensagemBmc(erro: unknown): string {
  const e = erro as { name?: string; codigo?: string };
  if (e?.name === 'ErroApi' && e.codigo !== undefined && MENSAGENS_BMC[e.codigo] !== undefined) {
    return MENSAGENS_BMC[e.codigo] as string;
  }
  return mensagemDeErro(erro);
}

export type ResultadoBmc =
  | { readonly ok: true; readonly mensagem: string; readonly resposta: RespostaBmc }
  | { readonly ok: false; readonly mensagem: string };

/** step-up -> POST /api/bmc/{power|status}. O `corpo` não é guardado em lugar nenhum. */
export async function executarBmc(
  rota: 'power' | 'status',
  corpo: CorpoBmc,
  deps: DependenciasBmc = REAIS,
): Promise<ResultadoBmc> {
  try {
    await deps.stepUp();
    const r = await deps.chamar(rota, corpo);
    const base = MENSAGENS_BMC[r.resultado] ?? 'Resposta do BMC recebida.';
    const extra = r.estado ? ` Estado de energia: ${r.estado.power_state}.` : '';
    return { ok: true, mensagem: base + extra, resposta: r };
  } catch (e) {
    return { ok: false, mensagem: mensagemBmc(e) };
  }
}
