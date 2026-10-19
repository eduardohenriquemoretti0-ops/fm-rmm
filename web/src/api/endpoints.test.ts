import { afterEach, describe, expect, it, vi } from 'vitest';
import { ErroApi } from './cliente';
import { iniciarLogin, lerSessao, listarAgentes } from './endpoints';

function json(corpo: unknown): Response {
  return new Response(JSON.stringify(corpo), { status: 200, headers: { 'Content-Type': 'application/json' } });
}

afterEach(() => vi.unstubAllGlobals());

describe('validação de contrato', () => {
  it('listarAgentes aceita lista bem formada', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json([{ id: 'a', hostname: 'h', os: 'o', online: true, ultimo_contato: null }])));
    await expect(listarAgentes()).resolves.toHaveLength(1);
  });

  it('listarAgentes recusa item com tipo errado', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json([{ id: 'a', hostname: 'h', os: 'o', online: 'sim', ultimo_contato: null }])));
    await expect(listarAgentes()).rejects.toBeInstanceOf(ErroApi);
  });

  it('listarAgentes recusa objeto no lugar de lista', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ itens: [] })));
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

  it('listarAgentes usa GET em /api/agents (contrato do handoff T4)', async () => {
    const f = vi.fn().mockResolvedValue(json([]));
    vi.stubGlobal('fetch', f);
    await listarAgentes();
    expect(f.mock.calls[0]?.[0]).toBe('/api/agents');
    expect((f.mock.calls[0]?.[1] as RequestInit).method).toBe('GET');
  });
});
