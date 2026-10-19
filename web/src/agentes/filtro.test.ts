import { describe, expect, it } from 'vitest';
import { filtrarAgentes, formatarUltimoContato } from './filtro';
import type { Agente } from '../api/tipos';

const lista: Agente[] = [
  { id: 'ag-01', hostname: 'SRV-Jundiai', os: 'Windows 10', status: 'aprovado', grupo: 'g1', online: true, ultimo_contato: null },
  { id: 'ag-02', hostname: 'pc-ana', os: 'Ubuntu 24.04', status: 'aprovado', grupo: 'g1', online: false, ultimo_contato: '2026-10-18T12:00:00Z' },
];

describe('filtrarAgentes', () => {
  it('termo vazio devolve tudo sem mutar a lista original', () => {
    const r = filtrarAgentes(lista, '   ');
    expect(r).toHaveLength(2);
    expect(r).not.toBe(lista);
  });

  it('busca por hostname, id e SO sem diferenciar caixa', () => {
    expect(filtrarAgentes(lista, 'jundiai').map((a) => a.id)).toEqual(['ag-01']);
    expect(filtrarAgentes(lista, 'AG-02').map((a) => a.id)).toEqual(['ag-02']);
    expect(filtrarAgentes(lista, 'ubuntu').map((a) => a.id)).toEqual(['ag-02']);
  });

  it('sem correspondência devolve vazio', () => {
    expect(filtrarAgentes(lista, 'inexistente')).toEqual([]);
  });
});

describe('formatarUltimoContato', () => {
  it('nunca contatou -> "Nunca"', () => {
    expect(formatarUltimoContato(null)).toBe('Nunca');
  });

  it('data inválida vira traço, sem ecoar o texto cru do servidor', () => {
    const cru = '<img src=x onerror=alert(1)>';
    expect(formatarUltimoContato(cru)).toBe('—');
  });

  it('data válida vira texto formatado (não ISO cru)', () => {
    const txt = formatarUltimoContato('2026-10-18T12:00:00Z');
    expect(txt).not.toContain('T12:00:00Z');
    expect(txt.length).toBeGreaterThan(0);
  });
});
