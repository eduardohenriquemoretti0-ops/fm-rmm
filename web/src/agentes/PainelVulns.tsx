/**
 * Painel de CVEs de um agente. Dado do servidor/agente sempre como texto do React.
 */
import { useEffect, useState } from 'react';
import { ErroApi } from '../api/cliente';
import { lerVulnerabilidades } from '../api/endpoints';
import type { ResumoVulnerabilidades } from '../api/tipos';
import { classeSeveridade, rotuloSeveridade } from './resumos';

/** Apresentação pura (testável sem rede). */
export function ConteudoVulns({ r }: { readonly r: ResumoVulnerabilidades }) {
  const naoAv = r.nao_avaliados_alto_risco.length;
  return (
    <>
      {!r.escaneado && <p>Este agente ainda não foi escaneado.</p>}
      {r.escaneado && r.vulnerabilidades.length === 0 && <p>Nenhuma vulnerabilidade encontrada.</p>}
      {r.vulnerabilidades.length > 0 && (
        <div className="tabela-rolagem">
          <table>
            <thead>
              <tr>
                <th scope="col">CVE</th>
                <th scope="col">Severidade</th>
                <th scope="col">Pontuação</th>
                <th scope="col">Pacote</th>
                <th scope="col">Versão corrigida</th>
              </tr>
            </thead>
            <tbody>
              {r.vulnerabilidades.map((v, i) => (
                <tr key={`${v.cve_id}-${v.pacote}-${i}`}>
                  <td>{v.cve_id}</td>
                  <td>
                    <span className={classeSeveridade(v.severidade)}>{rotuloSeveridade(v.severidade)}</span>
                  </td>
                  <td>{v.pontuacao === null ? '—' : v.pontuacao.toFixed(1)}</td>
                  <td>
                    {v.pacote} {v.versao}
                  </td>
                  <td>{v.fixed_version === '' ? '—' : v.fixed_version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {naoAv > 0 && (
        <p className="nota-risco" role="note">
          {naoAv} {naoAv === 1 ? 'item de alto risco sem fonte de CVE' : 'itens de alto risco sem fonte de CVE'}
        </p>
      )}
    </>
  );
}

export function PainelVulns({
  agenteId,
  hostname,
  aoFechar,
}: {
  readonly agenteId: string;
  readonly hostname: string;
  readonly aoFechar: () => void;
}) {
  const [estado, setEstado] = useState<
    | { readonly fase: 'carregando' }
    | { readonly fase: 'erro'; readonly mensagem: string }
    | { readonly fase: 'ok'; readonly dados: ResumoVulnerabilidades }
  >({ fase: 'carregando' });

  useEffect(() => {
    const ctrl = new AbortController();
    setEstado({ fase: 'carregando' });
    lerVulnerabilidades(agenteId, ctrl.signal)
      .then((dados) => setEstado({ fase: 'ok', dados }))
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === 'AbortError') return;
        setEstado({
          fase: 'erro',
          mensagem: e instanceof ErroApi ? e.message : 'Não foi possível carregar as vulnerabilidades.',
        });
      });
    return () => ctrl.abort();
  }, [agenteId]);

  return (
    <section className="painel-vulns" aria-label="Vulnerabilidades do agente">
      <header className="barra">
        <h3>Vulnerabilidades — {hostname}</h3>
        <button type="button" onClick={aoFechar}>
          Fechar
        </button>
      </header>
      {estado.fase === 'carregando' && <p role="status">Carregando…</p>}
      {estado.fase === 'erro' && (
        <p role="alert" className="erro">
          {estado.mensagem}
        </p>
      )}
      {estado.fase === 'ok' && <ConteudoVulns r={estado.dados} />}
    </section>
  );
}
