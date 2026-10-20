import { afterEach, describe, expect, it, vi } from 'vitest';
import { listarAcoesDisponiveis, listarBibliotecaScripts, listarCatalogoSoftware } from './endpoints';

function respostaJson(corpo: unknown): Response {
  return new Response(JSON.stringify(corpo), { status: 200, headers: { 'content-type': 'application/json' } });
}
afterEach(() => vi.unstubAllGlobals());

describe('consumo das listas', () => {
  it('lê catálogo e biblioteca nos caminhos do contrato e descarta campos extras', async () => {
    const f = vi.fn(async (url: string) =>
      url.endsWith('/api/catalogo-software')
        ? respostaJson({ versao: 1, itens: [{ id: 'vlc', nome: 'VLC', gerenciador: 'apt', pkg_id: 'NAO' }] })
        : respostaJson({ versao: 1, scripts: [{ id: 's', nome: 'S', versao: '1', interprete: 'sh', corpo: 'NAO' }] }),
    );
    vi.stubGlobal('fetch', f);
    const sw = await listarCatalogoSoftware();
    const sc = await listarBibliotecaScripts();
    expect(f.mock.calls.map((c) => c[0])).toEqual(['/api/catalogo-software', '/api/biblioteca-scripts']);
    expect(sw).toEqual([{ id: 'vlc', nome: 'VLC', gerenciador: 'apt' }]);
    expect(sc).toEqual([{ id: 's', nome: 'S', versao: '1', interprete: 'sh' }]);
  });

  it('valida a forma de /api/acoes-disponiveis (tipo desconhecido é recusado)', async () => {
    const boa = { nome: 'a', rotulo: 'A', origem: 'agente', rota: '/api/acoes', destrutiva: false, exige_step_up: true, so: ['linux'],
      params: [{ nome: 'mac', rotulo: 'm', obrigatorio: true, tipo: 'texto' }] };
    vi.stubGlobal('fetch', vi.fn(async () => respostaJson({ acoes: [boa] })));
    expect(await listarAcoesDisponiveis()).toHaveLength(1);
    const ruim = { ...boa, params: [{ nome: 'x', rotulo: 'x', obrigatorio: true, tipo: 'shell_livre' }] };
    vi.stubGlobal('fetch', vi.fn(async () => respostaJson({ acoes: [ruim] })));
    await expect(listarAcoesDisponiveis()).rejects.toThrow();
  });
});
