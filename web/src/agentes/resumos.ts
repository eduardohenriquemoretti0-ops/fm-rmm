/**
 * Formatação pura dos resumos do grid (vulnerabilidades, updates, saúde).
 * Nada aqui devolve texto cru do servidor: severidade desconhecida cai em
 * 'DESCONHECIDA' e as classes CSS vêm de uma lista fixa (nunca do dado).
 */
import type { SaudeResumo, UpdatesResumo, VulnCompacto } from '../api/tipos';

export type Severidade = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'DESCONHECIDA';

/** Da mais grave para a menos grave. */
export const ORDEM_SEVERIDADE: ReadonlyArray<Severidade> = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'DESCONHECIDA',
];

const ROTULOS: Readonly<Record<Severidade, string>> = {
  CRITICAL: 'Crítica',
  HIGH: 'Alta',
  MEDIUM: 'Média',
  LOW: 'Baixa',
  DESCONHECIDA: 'Desconhecida',
};

/** Normaliza a severidade vinda do servidor para o conjunto conhecido. */
export function normalizarSeveridade(s: string): Severidade {
  const u = s.toUpperCase();
  return (ORDEM_SEVERIDADE as ReadonlyArray<string>).includes(u) ? (u as Severidade) : 'DESCONHECIDA';
}

export function rotuloSeveridade(s: string): string {
  return ROTULOS[normalizarSeveridade(s)];
}

/** Classe CSS do badge (lista fixa). */
export function classeSeveridade(s: string): string {
  return `sev sev-${normalizarSeveridade(s).toLowerCase()}`;
}

/** Maior severidade com contagem > 0, ou null. */
export function maiorSeveridade(por: Readonly<Record<string, number>>): Severidade | null {
  const acumulado = new Map<Severidade, number>();
  for (const [k, n] of Object.entries(por)) {
    if (n > 0) {
      const sev = normalizarSeveridade(k);
      acumulado.set(sev, (acumulado.get(sev) ?? 0) + n);
    }
  }
  return ORDEM_SEVERIDADE.find((s) => acumulado.has(s)) ?? null;
}

export interface ResumoVulnView {
  readonly texto: string;
  /** Severidade do badge; null = sem badge. */
  readonly severidade: Severidade | null;
}

export function formatarVulns(v: VulnCompacto): ResumoVulnView {
  if (!v.escaneado) return { texto: '—', severidade: null };
  return { texto: String(v.total), severidade: v.total > 0 ? maiorSeveridade(v.por_severidade) : null };
}

export interface ResumoUpdatesView {
  readonly texto: string;
  readonly reinicio: boolean;
  /** pendente = atenção; ok = zero pendentes; desconhecido = traço. */
  readonly estado: 'ok' | 'pendente' | 'desconhecido';
}

export function formatarUpdates(u: UpdatesResumo): ResumoUpdatesView {
  if (u.pendentes === null) {
    return { texto: '—', reinicio: u.reinicio_pendente === true, estado: 'desconhecido' };
  }
  return {
    texto: String(u.pendentes),
    reinicio: u.reinicio_pendente === true,
    estado: u.pendentes > 0 ? 'pendente' : 'ok',
  };
}

export interface ResumoSaudeView {
  readonly texto: string;
  readonly estado: 'estavel' | 'instavel' | 'desconhecido';
}

export function formatarSaude(s: SaudeResumo): ResumoSaudeView {
  if (s.estavel === null) return { texto: '—', estado: 'desconhecido' };
  if (s.estavel) return { texto: 'Estável', estado: 'estavel' };
  const n = s.eventos;
  const sufixo = n === null ? '' : ` (${n} ${n === 1 ? 'evento' : 'eventos'})`;
  return { texto: `Instável${sufixo}`, estado: 'instavel' };
}
