/**
 * Lógica PURA dos formulários de ação (sem React, sem rede): a partir dos
 * metadados de GET /api/acoes-disponiveis monta os campos, valida e produz os
 * `params` do JobPayload.
 *
 * Regra de ouro: o operador só ESCOLHE (dropdown) ids vindos do servidor ou
 * digita um texto curto (ex.: MAC). Não existe campo para pkg_id, corpo de
 * script nem comando: o único tipo de entrada livre é `texto`, e o servidor o
 * valida contra o padrão do catálogo fechado.
 */
import type {
  AcaoDisponivel,
  Agente,
  ItemSoftware,
  ParamAcao,
  ScriptBiblioteca,
} from '../api/tipos';

export interface ListasFormulario {
  readonly software: ReadonlyArray<ItemSoftware>;
  readonly scripts: ReadonlyArray<ScriptBiblioteca>;
}

export interface Opcao {
  readonly valor: string;
  readonly texto: string;
}

export type Campo =
  | {
      readonly tipo: 'texto';
      readonly nome: string;
      readonly rotulo: string;
      readonly obrigatorio: boolean;
    }
  | {
      readonly tipo: 'select';
      readonly nome: string;
      readonly rotulo: string;
      readonly obrigatorio: boolean;
      /** Fonte das opções (para teste/diagnóstico). */
      readonly fonte: 'lista' | 'catalogo_software' | 'biblioteca_id' | 'biblioteca_versao';
      readonly opcoes: ReadonlyArray<Opcao>;
    }
  | {
      readonly tipo: 'confirmacao';
      readonly nome: string;
      readonly rotulo: string;
      readonly obrigatorio: true;
      /** Texto exato que o operador precisa digitar. */
      readonly esperado: string;
    };

export type Valores = Readonly<Record<string, string>>;

const TAMANHO_MAX_TEXTO = 128;

/** "WIPE-{agent_id}" -> "WIPE-<id>". Sem formato conhecido, falha fechado. */
export function confirmacaoEsperada(formato: string | undefined, agentId: string): string {
  const f = formato && formato.includes('{agent_id}') ? formato : 'WIPE-{agent_id}';
  return f.split('{agent_id}').join(agentId);
}

/** Ações de origem `agente` que o SO do agente suporta (os == GOOS do agente). */
export function acoesDoAgente(
  acoes: ReadonlyArray<AcaoDisponivel>,
  agente: Pick<Agente, 'os'>,
): AcaoDisponivel[] {
  const so = agente.os.toLowerCase();
  return acoes.filter((a) => a.origem === 'agente' && (a.so ?? []).includes(so));
}

function campoDoParam(
  p: ParamAcao,
  agente: Pick<Agente, 'id' | 'os'>,
  listas: ListasFormulario,
  valores: Valores,
): Campo {
  const base = { nome: p.nome, rotulo: p.rotulo, obrigatorio: p.obrigatorio };
  switch (p.tipo) {
    case 'lista': {
      const vs = p.valores_por_so?.[agente.os.toLowerCase()] ?? [];
      return { ...base, tipo: 'select', fonte: 'lista', opcoes: vs.map((v) => ({ valor: v, texto: v })) };
    }
    case 'item_catalogo_software':
      return {
        ...base,
        tipo: 'select',
        fonte: 'catalogo_software',
        opcoes: listas.software.map((i) => ({ valor: i.id, texto: `${i.nome} (${i.gerenciador})` })),
      };
    case 'script_biblioteca_id': {
      const vistos = new Set<string>();
      const opcoes: Opcao[] = [];
      for (const s of listas.scripts) {
        if (vistos.has(s.id)) continue;
        vistos.add(s.id);
        opcoes.push({ valor: s.id, texto: `${s.nome} (${s.interprete})` });
      }
      return { ...base, tipo: 'select', fonte: 'biblioteca_id', opcoes };
    }
    case 'script_biblioteca_versao': {
      // versões do script escolhido; sem script escolhido, nenhuma opção.
      const idEscolhido = valores['script_id'] ?? '';
      const opcoes = listas.scripts
        .filter((s) => s.id === idEscolhido)
        .map((s) => ({ valor: s.versao, texto: s.versao }));
      return { ...base, tipo: 'select', fonte: 'biblioteca_versao', opcoes };
    }
    case 'confirmacao_destrutiva':
      return {
        tipo: 'confirmacao',
        nome: p.nome,
        rotulo: p.rotulo,
        obrigatorio: true,
        esperado: confirmacaoEsperada(p.formato, agente.id),
      };
    case 'texto':
    default:
      return { ...base, tipo: 'texto' };
  }
}

/** Campos do formulário de uma ação de agente, na ordem dos params do servidor. */
export function camposDaAcao(
  acao: AcaoDisponivel,
  agente: Pick<Agente, 'id' | 'os'>,
  listas: ListasFormulario,
  valores: Valores = {},
): Campo[] {
  return acao.params.map((p) => campoDoParam(p, agente, listas, valores));
}

/** Valor do campo é aceitável? (selects: só opções oferecidas; confirmação: exata) */
export function campoValido(c: Campo, valor: string | undefined): boolean {
  const v = valor ?? '';
  switch (c.tipo) {
    case 'confirmacao':
      return v === c.esperado;
    case 'select':
      if (v === '') return !c.obrigatorio;
      return c.opcoes.some((o) => o.valor === v);
    case 'texto':
      if (v.trim() === '') return !c.obrigatorio;
      return v.length <= TAMANHO_MAX_TEXTO;
  }
}

export interface EstadoEnvio {
  /** Pode abrir o envio (e, se destrutiva, o diálogo)? */
  readonly podeSolicitar: boolean;
  /** Pode assinar/enviar agora? (destrutiva exige o diálogo confirmado) */
  readonly podeEnviar: boolean;
  readonly motivo: string | null;
}

/**
 * Habilitação do envio. Ação destrutiva só libera `podeEnviar` depois que a
 * confirmação digitada confere E o diálogo explícito foi confirmado.
 */
export function estadoEnvio(
  acao: AcaoDisponivel,
  campos: ReadonlyArray<Campo>,
  valores: Valores,
  dialogoConfirmado: boolean,
): EstadoEnvio {
  for (const c of campos) {
    if (!campoValido(c, valores[c.nome])) {
      const m =
        c.tipo === 'confirmacao'
          ? `Digite exatamente ${c.esperado}.`
          : `Preencha: ${c.rotulo}.`;
      return { podeSolicitar: false, podeEnviar: false, motivo: m };
    }
  }
  if (acao.destrutiva) {
    // falha fechado: ação destrutiva sem campo de confirmação nunca habilita
    if (!campos.some((c) => c.tipo === 'confirmacao')) {
      return { podeSolicitar: false, podeEnviar: false, motivo: 'Confirmação destrutiva indisponível.' };
    }
    if (!dialogoConfirmado) {
      return { podeSolicitar: true, podeEnviar: false, motivo: 'Falta confirmar no diálogo.' };
    }
  }
  return { podeSolicitar: true, podeEnviar: true, motivo: null };
}

/** `params` do JobPayload: só campos preenchidos, texto aparado (exceto confirmação). */
export function montarParams(campos: ReadonlyArray<Campo>, valores: Valores): Record<string, string> {
  const out: Record<string, string> = {};
  for (const c of campos) {
    const v = valores[c.nome] ?? '';
    if (v.trim() === '') continue;
    out[c.nome] = c.tipo === 'texto' ? v.trim() : v;
  }
  return out;
}
