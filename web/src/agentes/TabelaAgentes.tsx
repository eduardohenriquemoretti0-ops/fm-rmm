/**
 * Tabela de agentes (componente de apresentação puro).
 * Todo campo vindo do agente é renderizado como TEXTO (escape automático do React).
 * Nunca usar dangerouslySetInnerHTML nem v-html com dado de agente.
 */
import type { Agente } from '../api/tipos';
import { formatarUltimoContato } from './filtro';
import {
  classeSeveridade,
  formatarSaude,
  formatarUpdates,
  formatarVulns,
  rotuloSeveridade,
} from './resumos';

export function TabelaAgentes({
  agentes,
  aoConectar,
  aoEnviarInfo,
  aoVerVulns,
  aoAbrirAcoes,
}: {
  readonly agentes: ReadonlyArray<Agente>;
  readonly aoConectar: (agente: Agente) => void;
  readonly aoEnviarInfo?: (agente: Agente) => void;
  readonly aoVerVulns?: (agente: Agente) => void;
  readonly aoAbrirAcoes?: (agente: Agente) => void;
}) {
  return (
    <div className="tabela-rolagem">
      <table>
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Hostname</th>
            <th scope="col">SO</th>
            <th scope="col">Grupo</th>
            <th scope="col">Status</th>
            <th scope="col">Conexão</th>
            <th scope="col">Vulnerabilidades</th>
            <th scope="col">Updates</th>
            <th scope="col">Saúde</th>
            <th scope="col">Último contato</th>
            <th scope="col">Ação</th>
          </tr>
        </thead>
        <tbody>
          {agentes.map((a) => {
            const vuln = formatarVulns(a.vulnerabilidades);
            const upd = formatarUpdates(a.updates);
            const saude = formatarSaude(a.saude);
            return (
            <tr key={a.id}>
              <td>{a.id}</td>
              <td>{a.hostname}</td>
              <td>{a.os}</td>
              <td>{a.grupo}</td>
              <td>{a.status}</td>
              <td>{a.online ? 'Online' : 'Offline'}</td>
              <td data-col="vulns">
                {vuln.texto}
                {vuln.severidade !== null && (
                  <>
                    {' '}
                    <span className={classeSeveridade(vuln.severidade)}>
                      {rotuloSeveridade(vuln.severidade)}
                    </span>
                  </>
                )}
              </td>
              <td data-col="updates" className={`upd upd-${upd.estado}`}>
                {upd.texto}
                {upd.reinicio && (
                  <span className="reinicio" role="img" aria-label="Reinício pendente" title="Reinício pendente">
                    {' ⟳'}
                  </span>
                )}
              </td>
              <td data-col="saude" className={`saude saude-${saude.estado}`}>
                {saude.texto}
              </td>
              <td>{formatarUltimoContato(a.ultimo_contato)}</td>
              <td>
                <button type="button" data-modo="view" onClick={() => aoConectar(a)}>
                  Conectar
                </button>
                {aoVerVulns !== undefined && (
                  <button type="button" data-acao="vulns" onClick={() => aoVerVulns(a)}>
                    CVEs
                  </button>
                )}
                {aoAbrirAcoes !== undefined && (
                  <button type="button" data-acao="acoes" onClick={() => aoAbrirAcoes(a)}>
                    Ações
                  </button>
                )}
                {aoEnviarInfo !== undefined && (
                  <button type="button" data-acao="info" onClick={() => aoEnviarInfo(a)}>
                    Coletar info
                  </button>
                )}
              </td>
            </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
