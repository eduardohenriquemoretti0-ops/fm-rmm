/**
 * Funções puras do grid de agentes (sem React, testáveis).
 */
import type { Agente } from '../api/tipos';

/**
 * Filtra por id, hostname ou SO (sem diferenciar maiúsculas/minúsculas).
 * Termo vazio ou só espaços devolve a lista inteira.
 */
export function filtrarAgentes(lista: ReadonlyArray<Agente>, termo: string): Agente[] {
  const t = termo.trim().toLowerCase();
  if (t === '') return [...lista];
  return lista.filter(
    (a) =>
      a.id.toLowerCase().includes(t) ||
      a.hostname.toLowerCase().includes(t) ||
      a.os.toLowerCase().includes(t),
  );
}

/**
 * Formata o último contato para pt-BR. Nunca devolve o texto cru do servidor:
 * data inválida vira traço.
 */
export function formatarUltimoContato(iso: string | null): string {
  if (iso === null) return 'Nunca';
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return '—';
  return new Date(ms).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'medium' });
}
