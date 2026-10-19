/**
 * Grid de agentes (somente leitura). Todo dado do agente entra como TEXTO do
 * React (escape automático). Nunca usar dangerouslySetInnerHTML aqui.
 */
import { useEffect, useMemo, useState } from 'react';
import { ErroApi } from '../api/cliente';
import { listarAgentes } from '../api/endpoints';
import type { Agente } from '../api/tipos';
import { conectarAgente } from '../acoes/conectar';
import { useSessao } from '../auth/sessao';
import { filtrarAgentes } from './filtro';
import { TabelaAgentes } from './TabelaAgentes';

type Carga =
  | { readonly fase: 'carregando' }
  | { readonly fase: 'erro'; readonly mensagem: string }
  | { readonly fase: 'ok'; readonly agentes: Agente[] };

export function GridAgentes() {
  const { encerrar } = useSessao();
  const [carga, setCarga] = useState<Carga>({ fase: 'carregando' });
  const [termo, setTermo] = useState('');
  const [recarga, setRecarga] = useState(0);
  const [aviso, setAviso] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    setCarga({ fase: 'carregando' });
    listarAgentes(ctrl.signal)
      .then((agentes) => setCarga({ fase: 'ok', agentes }))
      .catch((erro: unknown) => {
        if (erro instanceof DOMException && erro.name === 'AbortError') return;
        if (erro instanceof ErroApi && erro.status === 401) {
          encerrar('Sessão expirou. Entre novamente.');
          return;
        }
        const mensagem =
          erro instanceof ErroApi ? erro.message : 'Não foi possível carregar os agentes.';
        setCarga({ fase: 'erro', mensagem });
      });
    return () => ctrl.abort();
  }, [encerrar, recarga]);

  const visiveis = useMemo(
    () => (carga.fase === 'ok' ? filtrarAgentes(carga.agentes, termo) : []),
    [carga, termo],
  );

  const total = carga.fase === 'ok' ? carga.agentes.length : 0;

  return (
    <section aria-labelledby="titulo-agentes">
      <header className="barra">
        <h2 id="titulo-agentes">Agentes</h2>
        <input
          type="search"
          placeholder="Buscar por id, hostname ou SO"
          aria-label="Buscar agentes"
          value={termo}
          onChange={(e) => setTermo(e.target.value)}
          disabled={carga.fase !== 'ok'}
        />
        <button type="button" onClick={() => setRecarga((n) => n + 1)}>
          Atualizar
        </button>
      </header>

      {carga.fase === 'carregando' && <p role="status">Carregando agentes…</p>}
      {carga.fase === 'erro' && (
        <p role="alert" className="erro">
          {carga.mensagem}
        </p>
      )}
      {aviso !== null && <p role="status">{aviso}</p>}

      {carga.fase === 'ok' && (
        <>
          <p className="contagem">
            {visiveis.length} de {total} agente(s)
          </p>
          <TabelaAgentes
            agentes={visiveis}
            aoConectar={(a) => setAviso(conectarAgente(a).motivo)}
          />
          {visiveis.length === 0 && total > 0 && (
            <p>Nenhum agente corresponde à busca.</p>
          )}
          {total === 0 && <p>Nenhum agente disponível para este operador.</p>}
        </>
      )}
    </section>
  );
}
