/**
 * Tabela de agentes (componente de apresentação puro).
 * Todo campo vindo do agente é renderizado como TEXTO (escape automático do React).
 * Nunca usar dangerouslySetInnerHTML nem v-html com dado de agente.
 */
import type { Agente } from '../api/tipos';
import { formatarUltimoContato } from './filtro';

export function TabelaAgentes({
  agentes,
  aoConectar,
  aoEnviarInfo,
}: {
  readonly agentes: ReadonlyArray<Agente>;
  readonly aoConectar: (agente: Agente) => void;
  readonly aoEnviarInfo?: (agente: Agente) => void;
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
            <th scope="col">Último contato</th>
            <th scope="col">Ação</th>
          </tr>
        </thead>
        <tbody>
          {agentes.map((a) => (
            <tr key={a.id}>
              <td>{a.id}</td>
              <td>{a.hostname}</td>
              <td>{a.os}</td>
              <td>{a.grupo}</td>
              <td>{a.status}</td>
              <td>{a.online ? 'Online' : 'Offline'}</td>
              <td>{formatarUltimoContato(a.ultimo_contato)}</td>
              <td>
                <button type="button" data-modo="view" onClick={() => aoConectar(a)}>
                  Conectar
                </button>
                {aoEnviarInfo !== undefined && (
                  <button type="button" data-acao="info" onClick={() => aoEnviarInfo(a)}>
                    Coletar info
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
