/**
 * Grid de agentes (somente leitura). Todo dado do agente entra como TEXTO do
 * React (escape automático). Nunca usar dangerouslySetInnerHTML aqui.
 */
import { useEffect, useMemo, useState } from 'react';
import { ErroApi } from '../api/cliente';
import { listarAgentes } from '../api/endpoints';
import type { Agente } from '../api/tipos';
import { conectarAgente, enviarJobInfo, mensagemDeErro, type ContextoAcao } from '../acoes/conectar';
import { registrarChaveAssinatura } from '../api/endpoints';
import type { Autenticador } from '../auth/assinatura';
import { montarRegistroChave } from '../auth/assinatura';
import { carregarAutenticador, gerarEGuardarAutenticador, armazemIndexedDB } from '../auth/armazem';
import { fazerStepUp } from '../auth/stepup';
import { useSessao } from '../auth/sessao';
import { filtrarAgentes } from './filtro';
import { TabelaAgentes } from './TabelaAgentes';
import { PainelVulns } from './PainelVulns';

type Carga =
  | { readonly fase: 'carregando' }
  | { readonly fase: 'erro'; readonly mensagem: string }
  | { readonly fase: 'ok'; readonly agentes: Agente[] };

export function GridAgentes() {
  const { estado, encerrar } = useSessao();
  const operador = estado.fase === 'autenticado' ? estado.operador : '';
  const tecnico = estado.fase === 'autenticado' ? estado.tecnico : undefined;
  const relayUrl = estado.fase === 'autenticado' ? estado.relayUrl : undefined;
  const [aut, setAut] = useState<Autenticador | null>(null);
  const [ocupado, setOcupado] = useState(false);
  const [carga, setCarga] = useState<Carga>({ fase: 'carregando' });
  const [termo, setTermo] = useState('');
  const [recarga, setRecarga] = useState(0);
  const [aviso, setAviso] = useState<string | null>(null);
  const [detalhe, setDetalhe] = useState<Agente | null>(null);

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

  // Recupera a chave de assinatura deste navegador (IndexedDB), se já existir.
  useEffect(() => {
    if (operador === '') return;
    let cancelado = false;
    carregarAutenticador(operador)
      .then((a) => {
        if (!cancelado) setAut(a);
      })
      .catch((e: unknown) => {
        if (!cancelado) setAviso(mensagemDeErro(e));
      });
    return () => {
      cancelado = true;
    };
  }, [operador]);

  const ctx: ContextoAcao = { operador, tecnico, relayUrl, assinador: aut };

  async function cadastrarChave(): Promise<void> {
    if (ocupado) return;
    setOcupado(true);
    setAviso(null);
    let criada = false;
    try {
      await fazerStepUp();
      const nova = await gerarEGuardarAutenticador(operador);
      criada = true;
      const r = await registrarChaveAssinatura(await montarRegistroChave(nova, operador));
      setAut(nova);
      setAviso(`Chave de assinatura registrada (key_id ${r.key_id}). Falta o admin publicá-la na lista de signers.`);
    } catch (e) {
      if (criada) await armazemIndexedDB.remover(operador).catch(() => undefined);
      setAviso(mensagemDeErro(e));
    } finally {
      setOcupado(false);
    }
  }

  async function rodar(f: () => Promise<{ mensagem: string }>): Promise<void> {
    if (ocupado) return;
    setOcupado(true);
    setAviso(null);
    try {
      setAviso((await f()).mensagem);
    } finally {
      setOcupado(false);
    }
  }

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
        {aut === null ? (
          <button type="button" disabled={ocupado} onClick={() => void cadastrarChave()}>
            Cadastrar chave de assinatura
          </button>
        ) : (
          <span>Chave de assinatura: {aut.keyId}</span>
        )}
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
            aoConectar={(a) => void rodar(() => conectarAgente(a, ctx))}
            aoEnviarInfo={(a) => void rodar(() => enviarJobInfo(a, ctx))}
            aoVerVulns={(a) => setDetalhe(a)}
          />
          {detalhe !== null && (
            <PainelVulns
              agenteId={detalhe.id}
              hostname={detalhe.hostname}
              aoFechar={() => setDetalhe(null)}
            />
          )}
          {visiveis.length === 0 && total > 0 && (
            <p>Nenhum agente corresponde à busca.</p>
          )}
          {total === 0 && <p>Nenhum agente disponível para este operador.</p>}
        </>
      )}
    </section>
  );
}
