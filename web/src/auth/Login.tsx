/**
 * Tela de login: cerimônia WebAuthn (inicio -> autenticador -> fim).
 * O cert mTLS do operador é apresentado pelo navegador no handshake; aqui só
 * tratamos o resultado.
 */
import { useRef, useState } from 'react';
import { finalizarLogin, iniciarLogin } from '../api/endpoints';
import { ErroApi } from '../api/cliente';
import { executarAsercao, mensagemErroWebAuthn } from './webauthn';
import { useSessao } from './sessao';

function mensagemErro(erro: unknown): string {
  if (erro instanceof ErroApi) {
    if (erro.status === 0) return erro.message;
    if (erro.status === 401 || erro.status === 403) {
      return 'Acesso recusado. Verifique o certificado de operador e a chave cadastrada.';
    }
    if (erro.status === 429) return erro.message;
    return 'Não foi possível concluir o login. Tente novamente.';
  }
  return mensagemErroWebAuthn(erro);
}

export function Login({
  aviso,
  aoRegistrar,
}: {
  readonly aviso?: string | undefined;
  readonly aoRegistrar?: (() => void) | undefined;
}) {
  const { aoAutenticar } = useSessao();
  const [ocupado, setOcupado] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  // Trava síncrona (ref): evita dois cliques na mesma renderização.
  const emCurso = useRef(false);

  async function entrar(): Promise<void> {
    if (emCurso.current) return;
    emCurso.current = true;
    setOcupado(true);
    setErro(null);
    try {
      const inicio = await iniciarLogin();
      const credencial = await executarAsercao(inicio.opcoes);
      const fim = await finalizarLogin(inicio.cerimonia, credencial);
      await aoAutenticar(fim.csrf);
    } catch (e) {
      setErro(mensagemErro(e));
    } finally {
      emCurso.current = false;
      setOcupado(false);
    }
  }

  return (
    <main className="login">
      <h1>FM-RMM — Console</h1>
      <p>Entre com sua chave de segurança (WebAuthn) para acessar o console.</p>
      {aviso !== undefined && <p role="status">{aviso}</p>}
      {erro !== null && (
        <p role="alert" className="erro">
          {erro}
        </p>
      )}
      <button type="button" onClick={() => void entrar()} disabled={ocupado}>
        {ocupado ? 'Aguardando o autenticador…' : 'Entrar com chave de segurança'}
      </button>
      {aoRegistrar !== undefined && (
        <p>
          <button type="button" className="link" onClick={aoRegistrar}>
            Primeiro acesso? Registrar chaves
          </button>
        </p>
      )}
    </main>
  );
}
