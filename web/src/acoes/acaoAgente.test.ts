import { webcrypto } from 'node:crypto';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { Autenticador, b64ParaBytes } from '../auth/assinatura';
import type { enviarAcao } from '../api/endpoints';
import { enviarAcaoDoPainel } from './acaoAgente';

let aut: Autenticador;
beforeAll(async () => {
  if ((globalThis as { crypto?: unknown }).crypto === undefined) vi.stubGlobal('crypto', webcrypto);
  aut = await Autenticador.dePar(await Autenticador.gerarPar());
});

describe('enviarAcaoDoPainel', () => {
  it('step-up -> assina -> envia, com params canônicos (só ids escolhidos)', async () => {
    const ordem: string[] = [];
    const enviar = vi.fn(async (_a: Parameters<typeof enviarAcao>[0]) => {
      ordem.push('enviar');
      return { estado: 'enfileirado', job: 'j1' };
    });
    const r = await enviarAcaoDoPainel(
      { id: 'agt-0001' },
      { nome: 'rodar_script', origem: 'agente' },
      { versao: '1.0.0', script_id: 'limpa-temp' },
      { operador: 'op-joao', assinador: aut },
      { stepUp: async () => void ordem.push('stepup'), enviar },
      () => new Date('2026-10-19T12:00:00Z'),
    );
    expect(r.ok).toBe(true);
    expect(ordem).toEqual(['stepup', 'enviar']);
    const c = enviar.mock.calls[0]?.[0] as Parameters<typeof enviarAcao>[0];
    const txt = new TextDecoder().decode(b64ParaBytes(c.payload));
    expect(txt).toContain('"action":"rodar_script","params":{"script_id":"limpa-temp","versao":"1.0.0"}');
  });

  it('sem chave de assinatura não envia nada; origem bmc é recusada', async () => {
    const enviar = vi.fn();
    const deps = { stepUp: vi.fn(async () => undefined), enviar: enviar as never };
    expect((await enviarAcaoDoPainel({ id: 'a' }, { nome: 'x', origem: 'agente' }, {}, { operador: 'o', assinador: null }, deps)).ok).toBe(false);
    expect((await enviarAcaoDoPainel({ id: 'a' }, { nome: 'bmc_power', origem: 'bmc' }, {}, { operador: 'o', assinador: aut }, deps)).ok).toBe(false);
    expect(enviar).not.toHaveBeenCalled();
    expect(deps.stepUp).not.toHaveBeenCalled();
  });
});
