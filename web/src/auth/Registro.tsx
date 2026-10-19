/**
 * Tela de registro de credencial WebAuthn do operador PENDENTE: duas chaves
 * físicas (principal + backup). Atrás do cert mTLS, sem sessão. Mesmo estilo do login.
 */
import { useRef, useState } from 'react';
import { ErroApi } from '../api/cliente';
import { mensagemErroWebAuthn } from './webauthn';
import { registrarCredencial } from './registro';

const ALVO = 2;
const ROTULOS = ['principal', 'de backup'] as const;

export function mensagemErroRegistro(erro: unknown): string {
  if (erro instanceof ErroApi) {
    if (erro.status === 0) return erro.message;
    if (erro.status === 403) return 'Cadastro de chaves indisponível: o operador não está pendente.';
    if (erro.status === 422) return 'Use uma chave física (não sincronizável).';
    if (erro.status === 429 || erro.status === 503) return erro.message;
    if (erro.status === 401) return 'Registro recusado. Verifique o certificado de operador e tente de novo.';
    return 'Não foi possível concluir o registro. Tente novamente.';
  }
  return mensagemErroWebAuthn(erro).replace('concluir o login', 'concluir o registro');
}

export function Registro({ aoVoltar }: { readonly aoVoltar: () => void }) {
  const [feitas, setFeitas] = useState(0);
  const [ocupado, setOcupado] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const emCurso = useRef(false);

  async function registrar(): Promise<void> {
    if (emCurso.current) return;
    emCurso.current = true;
    setOcupado(true);
    setErro(null);
    try {
      await registrarCredencial();
      setFeitas((n) => n + 1);
    } catch (e) {
      setErro(mensagemErroRegistro(e));
    } finally {
      emCurso.current = false;
      setOcupado(false);
    }
  }

  const completo = feitas >= ALVO;
  return (
    <main className="registro">
      <h1>FM-RMM — Registro de chaves</h1>
      <p>
        Registre duas chaves de segurança físicas: a principal e a de backup. Use chaves
        diferentes. Depois, o administrador ativa o operador.
      </p>
      <p role="status">
        Chaves registradas: {feitas} de {ALVO}
      </p>
      {erro !== null && (
        <p role="alert" className="erro">
          {erro}
        </p>
      )}
      {completo ? (
        <p role="status">Pronto. Avise o administrador para ativar o operador.</p>
      ) : (
        <button type="button" onClick={() => void registrar()} disabled={ocupado}>
          {ocupado
            ? 'Aguardando o autenticador…'
            : `Registrar chave ${ROTULOS[feitas] ?? ''}`.trim()}
        </button>
      )}
      <p>
        <button type="button" className="link" onClick={aoVoltar}>
          Voltar ao login
        </button>
      </p>
    </main>
  );
}
