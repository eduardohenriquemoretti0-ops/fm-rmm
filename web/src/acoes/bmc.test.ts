import { afterEach, describe, expect, it, vi } from 'vitest';
import { aposEnvio, executarBmc, FORM_BMC_VAZIO, validarFormBmc, type FormBmc } from './bmc';

const ACOES = ['On', 'ForceOff'];
const form: FormBmc = {
  host: '10.0.0.9', porta: '', system_id: '', acao: 'ForceOff', usuario: 'root', senha: 'S3gr3d0-unico!',
};

afterEach(() => vi.unstubAllGlobals());

function armadilhaStorage(): { acessos: string[] } {
  const acessos: string[] = [];
  const trap = new Proxy({}, {
    get: (_t, p) => { acessos.push(`get:${String(p)}`); return () => undefined; },
    set: (_t, p) => { acessos.push(`set:${String(p)}`); return true; },
  });
  vi.stubGlobal('localStorage', trap);
  vi.stubGlobal('sessionStorage', trap);
  return { acessos };
}

describe('credencial de BMC', () => {
  it('aposEnvio apaga usuário e senha e mantém o resto', () => {
    const r = aposEnvio(form);
    expect(r.usuario).toBe('');
    expect(r.senha).toBe('');
    expect(r.host).toBe('10.0.0.9');
    expect(JSON.stringify(r)).not.toContain('S3gr3d0');
  });

  it('não toca em localStorage/sessionStorage e o resultado não ecoa a credencial', async () => {
    const { acessos } = armadilhaStorage();
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const err = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const v = validarFormBmc(form, ACOES);
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    const chamar = vi.fn(async () => ({ resultado: 'ok', host: '10.0.0.9' }));
    const ordem: string[] = [];
    const r = await executarBmc('power', v.corpo, {
      stepUp: async () => void ordem.push('stepup'),
      chamar: ((...a: Parameters<typeof chamar>) => { ordem.push('chamar'); return chamar(...a); }) as never,
    });
    expect(ordem).toEqual(['stepup', 'chamar']);
    expect(chamar).toHaveBeenCalledOnce();
    expect(acessos).toEqual([]);
    expect(JSON.stringify(r)).not.toContain('S3gr3d0');
    expect(JSON.stringify(r)).not.toContain('root');
    expect(log).not.toHaveBeenCalled();
    expect(err).not.toHaveBeenCalled();
    log.mockRestore(); err.mockRestore();
  });

  it('falha (ErroApi) não ecoa credencial e traduz o código', async () => {
    const v = validarFormBmc(form, ACOES);
    if (!v.ok) throw new Error('inválido');
    const { ErroApi } = await import('../api/cliente');
    const r = await executarBmc('power', v.corpo, {
      stepUp: async () => undefined,
      chamar: async () => { throw new ErroApi(502, 'x', 'bmc_credencial_recusada'); },
    });
    expect(r.ok).toBe(false);
    expect(r.mensagem).toContain('recusou a credencial');
    expect(JSON.stringify(r)).not.toContain('S3gr3d0');
  });

  it('step-up que falha impede o envio', async () => {
    const v = validarFormBmc(form, ACOES);
    if (!v.ok) throw new Error('inválido');
    const chamar = vi.fn();
    const r = await executarBmc('power', v.corpo, {
      stepUp: async () => { throw Object.assign(new Error('x'), { name: 'NotAllowedError' }); },
      chamar: chamar as never,
    });
    expect(r.ok).toBe(false);
    expect(chamar).not.toHaveBeenCalled();
  });
});

describe('validação do formulário BMC', () => {
  it('porta padrão 443 e corpo com os campos do contrato', () => {
    const v = validarFormBmc(form, ACOES);
    expect(v).toMatchObject({ ok: true, corpo: { host: '10.0.0.9', porta: 443, acao: 'ForceOff', usuario: 'root' } });
    if (v.ok) expect(Object.keys(v.corpo).sort()).toEqual(['acao', 'host', 'porta', 'senha', 'system_id', 'usuario']);
  });
  it('recusa ação fora da lista do servidor, porta inválida e credencial vazia', () => {
    expect(validarFormBmc({ ...form, acao: 'rm -rf' }, ACOES).ok).toBe(false);
    expect(validarFormBmc({ ...form, porta: '70000' }, ACOES).ok).toBe(false);
    expect(validarFormBmc({ ...form, senha: '' }, ACOES).ok).toBe(false);
    expect(validarFormBmc(FORM_BMC_VAZIO, ACOES).ok).toBe(false);
  });
});
