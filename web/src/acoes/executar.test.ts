import { webcrypto } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { Autenticador, b64ParaBytes } from '../auth/assinatura';
import { definirCsrf } from '../api/cliente';
import { enviarAcao } from '../api/endpoints';
import { conectarAgente, enviarJobInfo } from './conectar';
import type { Agente } from '../api/tipos';

const agente: Agente = {
  id: 'agt-0001', hostname: 'h', os: 'linux', status: 'aprovado', grupo: 'g', online: true, ultimo_contato: null,
  vulnerabilidades: { escaneado: false, escaneado_em: null, total: 0, por_severidade: {} }, updates: { pendentes: null, reinicio_pendente: null }, saude: { estavel: null, eventos: null },
};
let aut: Autenticador;

beforeAll(async () => {
  if ((globalThis as { crypto?: unknown }).crypto === undefined) vi.stubGlobal('crypto', webcrypto);
  aut = await Autenticador.dePar(await Autenticador.gerarPar());
});
afterEach(() => {
  vi.unstubAllGlobals();
  definirCsrf(null);
  if ((globalThis as { crypto?: unknown }).crypto === undefined) vi.stubGlobal('crypto', webcrypto);
});

describe('fluxo de ação', () => {
  it('step-up ANTES da assinatura; envia {tipo,payload,sig,key_id} com base64 dos bytes', async () => {
    const ordem: string[] = [];
    const enviar = vi.fn(async (a: Parameters<typeof enviarAcao>[0]) => {
      ordem.push('enviar');
      return { estado: 'enfileirado', job: a.key_id };
    });
    const r = await enviarJobInfo(
      agente,
      { operador: 'op-joao', assinador: aut },
      { stepUp: async () => void ordem.push('stepup'), enviar },
      () => new Date('2026-10-19T12:00:00.400Z'),
    );
    expect(r.ok).toBe(true);
    expect(ordem).toEqual(['stepup', 'enviar']);
    const corpo = enviar.mock.calls[0]?.[0] as Parameters<typeof enviarAcao>[0];
    expect(Object.keys(corpo).sort()).toEqual(['key_id', 'payload', 'sig', 'tipo']);
    const txt = new TextDecoder().decode(b64ParaBytes(corpo.payload));
    expect(txt).toMatch(/^\{"v":1,"job_id":"job-[0-9a-f]{16}","agent_id":"agt-0001","action":"info","issued_at":"2026-10-19T12:00:00Z","expires_at":"2026-10-19T12:10:00Z","issuer":"op-joao"\}$/);
    expect(corpo.key_id).toBe(aut.keyId);
  });

  it('Conectar monta grant assinado; sem tecnico/relay do servidor falha fechado', async () => {
    const enviar = vi.fn(async () => ({ estado: 'enfileirado', sessao: 's' }));
    const deps = { stepUp: async () => undefined, enviar };
    const sem = await conectarAgente(agente, { operador: 'op-joao', assinador: aut }, deps);
    expect(sem.ok).toBe(false);
    expect(enviar).not.toHaveBeenCalled();
    const ok = await conectarAgente(
      agente,
      { operador: 'op-joao', tecnico: 'joao', relayUrl: 'wss://relay.exemplo:8443/r', assinador: aut },
      deps,
    );
    expect(ok.ok).toBe(true);
    const corpo = (enviar.mock.calls[0] as unknown as [Parameters<typeof enviarAcao>[0]])[0];
    const g = JSON.parse(new TextDecoder().decode(b64ParaBytes(corpo.payload))) as Record<string, string>;
    expect(g.mode).toBe('view');
    expect(g.technician).toBe('joao');
    expect(g.relay_token?.length).toBeGreaterThanOrEqual(32);
  });

  it('sem chave cadastrada não envia nada', async () => {
    const enviar = vi.fn();
    const r = await enviarJobInfo(agente, { operador: 'op', assinador: null }, { stepUp: async () => undefined, enviar });
    expect(r.ok).toBe(false);
    expect(enviar).not.toHaveBeenCalled();
  });

  it('falha no step-up impede a assinatura e o envio', async () => {
    const enviar = vi.fn();
    const r = await enviarJobInfo(agente, { operador: 'op', assinador: aut }, {
      stepUp: async () => { throw new Error('cancelado'); }, enviar,
    });
    expect(r.ok).toBe(false);
    expect(enviar).not.toHaveBeenCalled();
  });
});

describe('POST /api/acoes (cliente HTTP)', () => {
  it('credentials include + header X-FMRMM-CSRF + corpo exato', async () => {
    definirCsrf('csrf-teste');
    const f = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ job: 'j', estado: 'enfileirado' }), {
        status: 202, headers: { 'Content-Type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', f);
    const acao = { tipo: 'job' as const, payload: 'AAAA', sig: 'BBBB', key_id: '56475aa75463474c' };
    await expect(enviarAcao(acao)).resolves.toEqual({ job: 'j', estado: 'enfileirado' });
    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/acoes');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('include');
    expect((init.headers as Headers).get('X-FMRMM-CSRF')).toBe('csrf-teste');
    expect(JSON.parse(init.body as string)).toEqual(acao);
  });

  it('403 step_up_necessario vira ErroApi com codigo (sem ecoar corpo)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ erro: 'step_up_necessario', step_up: true }), {
        status: 403, headers: { 'Content-Type': 'application/json' },
      }),
    ));
    const e = await enviarAcao({ tipo: 'job', payload: 'a', sig: 'b', key_id: 'c' }).catch((x: unknown) => x);
    expect((e as { codigo?: string }).codigo).toBe('step_up_necessario');
    expect((e as Error).message).not.toContain('step_up_necessario');
  });
});
