/**
 * Casca da SPA: decide entre a tela de login e o console (grid de agentes).
 */
import { useState } from 'react';
import { Login } from './auth/Login';
import { Registro } from './auth/Registro';
import { ProvedorSessao, useSessao } from './auth/sessao';
import { GridAgentes } from './agentes/GridAgentes';

function Casca() {
  const { estado, sair } = useSessao();
  const [registrando, setRegistrando] = useState(false);

  if (estado.fase === 'carregando') {
    return <p role="status" className="centro">Verificando sessão…</p>;
  }
  if (estado.fase === 'anonimo') {
    if (registrando) return <Registro aoVoltar={() => setRegistrando(false)} />;
    return <Login aviso={estado.aviso} aoRegistrar={() => setRegistrando(true)} />;
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
