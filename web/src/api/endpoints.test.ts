import { afterEach, describe, expect, it, vi } from 'vitest';
import { ErroApi } from './cliente';
import { iniciarLogin, lerSessao, listarAgentes } from './endpoints';

function json(corpo: unknown): Response {
  return new Response(JSON.stringify(corpo), { status: 200, headers: { 'Content-Type': 'application/json' } });
}

afterEach(() => vi.unstubAllGlobals());

describe('validação de contrato', () => {
  it('listarAgentes aceita lista bem formada', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ agentes: [{ id: 'a', hostname: 'h', os: 'o', status: 'aprovado', grupo: 'g', online: true, ultimo_contato: null, vulnerabilidades: { escaneado: false, escaneado_em: null, total: 0, por_severidade: {} }, updates: { pendentes: null, reinicio_pendente: null }, saude: { estavel: null, eventos: null } }] })));
    await expect(listarAgentes()).resolves.toHaveLength(1);
  });

  it('listarAgentes recusa item com tipo errado', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ agentes: [{ id: 'a', hostname: 'h', os: 'o', status: 'aprovado', grupo: 'g', online: 'sim', ultimo_contato: null, vulnerabilidades: { escaneado: false, escaneado_em: null, total: 0, por_severidade: {} }, updates: { pendentes: null, reinicio_pendente: null }, saude: { estavel: null, eventos: null } }] })));
    await expect(listarAgentes()).rejects.toBeInstanceOf(ErroApi);
  });

  it('listarAgentes recusa lista pura (o T4 devolve {agentes:[...]})', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json([])));
    await expect(listarAgentes()).rejects.toBeInstanceOf(ErroApi);
  });

  it('lerSessao exige operador, nome e csrf', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ operador: 'op-a', csrf: 'c' })));
    await expect(lerSessao()).rejects.toBeInstanceOf(ErroApi);
  });

  it('iniciarLogin exige cerimonia e opcoes.publicKey.challenge', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ cerimonia: 'k', opcoes: {} })));
    await expect(iniciarLogin()).rejects.toBeInstanceOf(ErroApi);
  });

  it('listarAgentes usa GET em /api/agentes (rota real do T4)', async () => {
    const f = vi.fn().mockResolvedValue(json({ agentes: [] }));
    vi.stubGlobal('fetch', f);
    await listarAgentes();
    expect(f.mock.calls[0]?.[0]).toBe('/api/agentes');
    expect((f.mock.calls[0]?.[1] as RequestInit).method).toBe('GET');
  });
});

describe('shape novo da lista de agentes', () => {
  const base = { id: 'a', hostname: 'h', os: 'o', status: 'aprovado', grupo: 'g', online: true, ultimo_contato: null };
  const novo = {
    vulnerabilidades: { escaneado: true, escaneado_em: '2026-10-18T10:00:00Z', total: 2, por_severidade: { HIGH: 2 } },
    updates: { pendentes: 3, reinicio_pendente: false, aviso: 'x' },
    saude: { estavel: false, eventos: 4 },
  };
  it('aceita o shape completo (inclui aviso opcional)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ agentes: [{ ...base, ...novo }] })));
    const [a] = await listarAgentes();
    expect(a?.vulnerabilidades.total).toBe(2);
    expect(a?.saude.eventos).toBe(4);
  });
  it('recusa campos novos ausentes ou malformados', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ agentes: [base] })));
    await expect(listarAgentes()).rejects.toBeInstanceOf(ErroApi);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ agentes: [{ ...base, ...novo, saude: { estavel: 'sim', eventos: 1 } }] })));
    await expect(listarAgentes()).rejects.toBeInstanceOf(ErroApi);
  });
});
