/**
 * Estado de sessão do console (React context).
 *
 * - O cookie de sessão é HttpOnly: aqui NÃO há leitura de cookie nem token.
 * - O CSRF entra em memória via definirCsrf() (api/cliente.ts) e some ao recarregar
 *   a página ou ao sair. Nunca vai para localStorage/sessionStorage.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { ErroApi, definirCsrf } from '../api/cliente';
import { lerSessao, sair as sairApi } from '../api/endpoints';
import type { RespostaSessao } from '../api/tipos';

export type EstadoSessao =
  | { readonly fase: 'carregando' }
  | { readonly fase: 'anonimo'; readonly aviso?: string }
  | {
      readonly fase: 'autenticado';
      readonly operador: string;
      readonly nome: string;
      /** TechName e relay do servidor (opcionais até o backend expô-los). */
      readonly tecnico?: string;
      readonly relayUrl?: string;
    };

export interface ValorSessao {
  readonly estado: EstadoSessao;
  /** Chamado após o /fim do login: guarda o CSRF e confirma a sessão com o servidor. */
  aoAutenticar(csrf: string): Promise<void>;
  /** Encerra a sessão local (ex.: 401 durante o uso). */
  encerrar(aviso?: string): void;
  /** Revoga no servidor (POST /api/logout) e limpa o estado local em qualquer caso. */
  sair(): Promise<void>;
}

const ContextoSessao = createContext<ValorSessao | null>(null);

function autenticado(s: RespostaSessao): EstadoSessao {
  return {
    fase: 'autenticado',
    operador: s.operador,
    nome: s.nome,
    ...(s.tecnico !== undefined ? { tecnico: s.tecnico } : {}),
    ...(s.relay_url !== undefined ? { relayUrl: s.relay_url } : {}),
  };
}

export function ProvedorSessao({ children }: { readonly children: ReactNode }) {
  const [estado, setEstado] = useState<EstadoSessao>({ fase: 'carregando' });

  // Verifica se já existe sessão válida (cookie HttpOnly enviado pelo navegador).
  useEffect(() => {
    let cancelado = false;
    lerSessao()
      .then((s) => {
        if (cancelado) return;
        definirCsrf(s.csrf);
        setEstado(autenticado(s));
      })
      .catch((erro: unknown) => {
        if (cancelado) return;
        definirCsrf(null);
        const semSessao = erro instanceof ErroApi && erro.status === 401;
        setEstado({
          fase: 'anonimo',
          ...(semSessao ? {} : { aviso: 'Não foi possível verificar a sessão.' }),
        });
      });
    return () => {
      cancelado = true;
    };
  }, []);

  const aoAutenticar = useCallback(async (csrf: string): Promise<void> => {
    definirCsrf(csrf);
    try {
      const s = await lerSessao();
      definirCsrf(s.csrf);
      setEstado(autenticado(s));
    } catch {
      definirCsrf(null);
      setEstado({ fase: 'anonimo', aviso: 'Sessão não confirmada pelo servidor.' });
    }
  }, []);

  const encerrar = useCallback((aviso?: string) => {
    definirCsrf(null);
    setEstado(aviso !== undefined ? { fase: 'anonimo', aviso } : { fase: 'anonimo' });
  }, []);

  const sair = useCallback(async (): Promise<void> => {
    try {
      await sairApi();
      encerrar();
    } catch {
      encerrar('Sessão encerrada aqui. O servidor pode não ter confirmado a revogação.');
    }
  }, [encerrar]);

  const valor = useMemo<ValorSessao>(
    () => ({ estado, aoAutenticar, encerrar, sair }),
    [estado, aoAutenticar, encerrar, sair],
  );

  return <ContextoSessao.Provider value={valor}>{children}</ContextoSessao.Provider>;
}

/** Acesso ao estado de sessão. Deve ser usado dentro de ProvedorSessao. */
export function useSessao(): ValorSessao {
  const valor = useContext(ContextoSessao);
  if (valor === null) {
    throw new Error('useSessao fora de ProvedorSessao');
  }
  return valor;
}
