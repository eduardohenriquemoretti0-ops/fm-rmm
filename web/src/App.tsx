/**
 * Casca da SPA: decide entre a tela de login e o console (grid de agentes).
 */
import { Login } from './auth/Login';
import { ProvedorSessao, useSessao } from './auth/sessao';
import { GridAgentes } from './agentes/GridAgentes';

function Casca() {
  const { estado, sair } = useSessao();

  if (estado.fase === 'carregando') {
    return <p role="status" className="centro">Verificando sessão…</p>;
  }
  if (estado.fase === 'anonimo') {
    return <Login aviso={estado.aviso} />;
  }
  return (
    <>
      <header className="topo">
        <strong>FM-RMM — Console</strong>
        <span>
          Operador: {estado.nome} ({estado.operador})
        </span>
        <button type="button" onClick={() => void sair()}>
          Sair
        </button>
      </header>
      <main>
        <GridAgentes />
      </main>
    </>
  );
}

export function App() {
  return (
    <ProvedorSessao>
      <Casca />
    </ProvedorSessao>
  );
}
