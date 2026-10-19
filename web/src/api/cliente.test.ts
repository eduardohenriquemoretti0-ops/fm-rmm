import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CABECALHO_CSRF,
  chamarApi,
  definirCsrf,
  ErroApi,
  obterCsrf,
} from './cliente';

function respostaJson(corpo: unknown, status = 200): Response {
  return new Response(JSON.stringify(corpo), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('cliente HTTP', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let setItem: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    definirCsrf(null);
    // uma Response NOVA por chamada (um Response só pode ser lido uma vez)
    fetchMock = vi.fn().mockImplementation(() => Promise.resolve(respostaJson({ ok: true })));
    vi.stubGlobal('fetch', fetchMock);
    setItem = vi.fn();
    vi.stubGlobal('localStorage', { setItem, getItem: vi.fn(), removeItem: vi.fn() });
    vi.stubGlobal('sessionStorage', { setItem, getItem: vi.fn(), removeItem: vi.fn() });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    definirCsrf(null);
  });

  it('envia credentials include, sem referrer e sem cache', async () => {
    await chamarApi('/api/sessao');
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(init.credentials).toBe('include');
    expect(init.referrerPolicy).toBe('no-referrer');
    expect(init.cache).toBe('no-store');
    expect(init.redirect).toBe('error');
  });

  it('CSRF só vai em escrita e só depois de definido', async () => {
    await chamarApi('/api/logout', { metodo: 'POST' });
    const h1 = (fetchMock.mock.calls[0]?.[1] as RequestInit).headers as Headers;
    expect(h1.get(CABECALHO_CSRF)).toBeNull();

    definirCsrf('token-em-memoria');
    await chamarApi('/api/logout', { metodo: 'POST' });
    const h2 = (fetchMock.mock.calls[1]?.[1] as RequestInit).headers as Headers;
    expect(h2.get(CABECALHO_CSRF)).toBe('token-em-memoria');

    await chamarApi('/api/agents');
    const h3 = (fetchMock.mock.calls[2]?.[1] as RequestInit).headers as Headers;
    expect(h3.get(CABECALHO_CSRF)).toBeNull();
  });

  it('nunca grava CSRF nem nada em localStorage/sessionStorage', async () => {
    definirCsrf('x');
    await chamarApi('/api/logout', { metodo: 'POST' });
    definirCsrf(null);
    expect(setItem).not.toHaveBeenCalled();
    expect(obterCsrf()).toBeNull();
  });

  it('HTTP de erro vira ErroApi com mensagem genérica (não ecoa o corpo)', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response('stacktrace interno: senha=abc', {
        status: 500,
        headers: { 'Content-Type': 'text/plain' },
      }),
    );
    const erro = await chamarApi('/api/agents').catch((e: unknown) => e);
    expect(erro).toBeInstanceOf(ErroApi);
    expect((erro as ErroApi).status).toBe(500);
    expect((erro as ErroApi).message).not.toContain('senha');
    expect((erro as ErroApi).message).not.toContain('stacktrace');
  });

  it('401 sinaliza sessão ausente', async () => {
    fetchMock.mockResolvedValueOnce(respostaJson({ erro: 'x' }, 401));
    const erro = (await chamarApi('/api/sessao').catch((e: unknown) => e)) as ErroApi;
    expect(erro.status).toBe(401);
    expect(erro.message).toContain('expirada');
  });

  it('falha de rede (ex.: mTLS recusado no handshake) vira status 0', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    const erro = (await chamarApi('/api/sessao').catch((e: unknown) => e)) as ErroApi;
    expect(erro.status).toBe(0);
    expect(erro.message).toContain('certificado');
  });

  it('resposta não-JSON é recusada', async () => {
    fetchMock.mockResolvedValueOnce(new Response('<html>', { status: 200, headers: { 'Content-Type': 'text/html' } }));
    await expect(chamarApi('/api/sessao')).rejects.toBeInstanceOf(ErroApi);
  });

  it('recusa caminho fora de /api/ (sem SSRF/host externo)', async () => {
    await expect(chamarApi('https://evil.example/x')).rejects.toBeInstanceOf(ErroApi);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
