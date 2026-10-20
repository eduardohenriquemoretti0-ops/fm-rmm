/**
 * Painel "Ações" de um agente: lista as ações de escrita aplicáveis ao SO e
 * monta o formulário a partir dos `params` do servidor. Envio: (diálogo, se
 * destrutiva) -> step-up -> assinatura no navegador -> POST /api/acoes.
 */
import { useMemo, useState } from 'react';
import type { AcaoDisponivel, Agente } from '../api/tipos';
import { enviarAcaoDoPainel } from '../acoes/acaoAgente';
import type { ContextoAcao } from '../acoes/conectar';
import {
  acoesDoAgente,
  camposDaAcao,
  estadoEnvio,
  montarParams,
  type ListasFormulario,
  type Valores,
} from '../acoes/formulario';
import { DialogoDestrutivo, FormularioAcao } from './FormularioAcao';

export function PainelAcoes({
  agente,
  acoes,
  listas,
  ctx,
  aoFechar,
}: {
  readonly agente: Agente;
  readonly acoes: ReadonlyArray<AcaoDisponivel>;
  readonly listas: ListasFormulario;
  readonly ctx: ContextoAcao;
  readonly aoFechar: () => void;
}) {
  const aplicaveis = useMemo(() => acoesDoAgente(acoes, agente), [acoes, agente]);
  const [nomeAcao, setNomeAcao] = useState<string | null>(null);
  const [valores, setValores] = useState<Valores>({});
  const [dialogo, setDialogo] = useState(false);
  const [ocupado, setOcupado] = useState(false);
  const [resultado, setResultado] = useState<{ ok: boolean; mensagem: string } | null>(null);

  const acao = aplicaveis.find((a) => a.nome === nomeAcao) ?? null;
  const campos = acao ? camposDaAcao(acao, agente, listas, valores) : [];
  const estado = acao ? estadoEnvio(acao, campos, valores, dialogo) : null;

  function escolher(nome: string): void {
    setNomeAcao(nome);
    setValores({});
    setDialogo(false);
    setResultado(null);
  }

  function mudar(nome: string, valor: string): void {
    // trocar o script invalida a versão escolhida
    setValores((v) => ({ ...v, [nome]: valor, ...(nome === 'script_id' ? { versao: '' } : {}) }));
  }

  async function enviar(): Promise<void> {
    if (acao === null || estado === null || ocupado) return;
    // recomputa na hora do envio; ação destrutiva só passa com o diálogo aberto/confirmado
    const pronto = estadoEnvio(acao, campos, valores, dialogo);
    if (!pronto.podeEnviar) return;
    setOcupado(true);
    setResultado(null);
    try {
      const r = await enviarAcaoDoPainel(agente, acao, montarParams(campos, valores), ctx);
      setResultado(r);
      if (r.ok) setValores({});
    } finally {
      setDialogo(false);
      setOcupado(false);
    }
  }

  return (
    <section className="painel-acoes" aria-label={`Ações de ${agente.hostname}`}>
      <header className="barra">
        <h3>Ações — {agente.hostname}</h3>
        <button type="button" onClick={aoFechar}>
          Fechar
        </button>
      </header>
      {aplicaveis.length === 0 && <p>Nenhuma ação de escrita disponível para este sistema ({agente.os}).</p>}
      <ul className="lista-acoes">
        {aplicaveis.map((a) => (
          <li key={a.nome}>
            <button
              type="button"
              className={a.destrutiva ? 'perigo' : undefined}
              aria-pressed={a.nome === nomeAcao}
              onClick={() => escolher(a.nome)}
            >
              {a.nome}
            </button>
          </li>
        ))}
      </ul>
      {acao !== null && estado !== null && (
        <FormularioAcao
          key={acao.nome}
          acao={acao}
          campos={campos}
          valores={valores}
          estado={estado}
          ocupado={ocupado}
          aoMudar={mudar}
          aoSolicitar={() => (acao.destrutiva ? setDialogo(true) : void enviar())}
        />
      )}
      {dialogo && acao !== null && (
        <DialogoDestrutivo
          agente={`${agente.hostname} (${agente.id})`}
          aoCancelar={() => setDialogo(false)}
          aoConfirmar={() => void enviar()}
        />
      )}
      {resultado !== null && (
        <p role={resultado.ok ? 'status' : 'alert'} className={resultado.ok ? undefined : 'erro'}>
          {resultado.mensagem}
        </p>
      )}
    </section>
  );
}
