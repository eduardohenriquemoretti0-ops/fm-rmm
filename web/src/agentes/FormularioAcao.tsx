/**
 * Formulário de UMA ação de agente (apresentação pura). Todo texto vindo do
 * servidor/agente entra como TEXTO do React. Sem dangerouslySetInnerHTML, sem
 * estilo inline. Os únicos controles são <select> (ids vindos do servidor) e
 * um <input> de texto curto para params `texto` (ex.: MAC) e para a
 * confirmação destrutiva — nunca há campo de pkg_id, corpo ou comando.
 */
import type { AcaoDisponivel } from '../api/tipos';
import type { Campo, EstadoEnvio, Valores } from '../acoes/formulario';

function CampoView({
  campo,
  valor,
  aoMudar,
  desabilitado,
}: {
  readonly campo: Campo;
  readonly valor: string;
  readonly aoMudar: (nome: string, valor: string) => void;
  readonly desabilitado: boolean;
}) {
  const id = `campo-${campo.nome}`;
  return (
    <div className="campo">
      <label htmlFor={id}>
        {campo.rotulo}
        {campo.obrigatorio ? ' *' : ''}
      </label>
      {campo.tipo === 'select' ? (
        <select
          id={id}
          name={campo.nome}
          value={valor}
          disabled={desabilitado}
          onChange={(e) => aoMudar(campo.nome, e.target.value)}
        >
          <option value="">— escolha —</option>
          {campo.opcoes.map((o) => (
            <option key={o.valor} value={o.valor}>
              {o.texto}
            </option>
          ))}
        </select>
      ) : (
        <input
          id={id}
          name={campo.nome}
          type="text"
          value={valor}
          maxLength={128}
          autoComplete="off"
          spellCheck={false}
          disabled={desabilitado}
          placeholder={campo.tipo === 'confirmacao' ? campo.esperado : undefined}
          onChange={(e) => aoMudar(campo.nome, e.target.value)}
        />
      )}
      {campo.tipo === 'confirmacao' && (
        <small className="dica-confirmacao">
          Digite exatamente: <code>{campo.esperado}</code>
        </small>
      )}
    </div>
  );
}

export function FormularioAcao({
  acao,
  campos,
  valores,
  estado,
  ocupado,
  aoMudar,
  aoSolicitar,
}: {
  readonly acao: AcaoDisponivel;
  readonly campos: ReadonlyArray<Campo>;
  readonly valores: Valores;
  readonly estado: EstadoEnvio;
  readonly ocupado: boolean;
  readonly aoMudar: (nome: string, valor: string) => void;
  readonly aoSolicitar: () => void;
}) {
  return (
    <form
      className={acao.destrutiva ? 'acao-form acao-destrutiva' : 'acao-form'}
      data-acao={acao.nome}
      onSubmit={(e) => {
        e.preventDefault();
        if (estado.podeSolicitar && !ocupado) aoSolicitar();
      }}
    >
      <h4>{acao.rotulo}</h4>
      {acao.destrutiva && (
        <p role="alert" className="aviso-destrutivo">
          ATENÇÃO: ação DESTRUTIVA e IRREVERSÍVEL. Os dados da máquina serão perdidos.
        </p>
      )}
      {campos.map((c) => (
        <CampoView
          key={c.nome}
          campo={c}
          valor={valores[c.nome] ?? ''}
          aoMudar={aoMudar}
          desabilitado={ocupado}
        />
      ))}
      <button
        type="submit"
        className={acao.destrutiva ? 'perigo' : undefined}
        disabled={!estado.podeSolicitar || ocupado}
      >
        {acao.destrutiva ? 'Apagar máquina…' : 'Enviar ação'}
      </button>
      {!estado.podeSolicitar && estado.motivo !== null && (
        <small className="motivo-bloqueio">{estado.motivo}</small>
      )}
    </form>
  );
}

/** Diálogo explícito exigido antes de assinar/enviar uma ação destrutiva. */
export function DialogoDestrutivo({
  agente,
  aoConfirmar,
  aoCancelar,
}: {
  readonly agente: string;
  readonly aoConfirmar: () => void;
  readonly aoCancelar: () => void;
}) {
  return (
    <div className="dialogo-fundo">
      <div role="alertdialog" aria-modal="true" aria-labelledby="dlg-titulo" className="dialogo perigo-caixa">
        <h3 id="dlg-titulo">Isto apaga a máquina</h3>
        <p>
          Você está prestes a executar um cripto-erase IRREVERSÍVEL em <strong>{agente}</strong>.
          Depois disso não há como recuperar os dados. Seu navegador pedirá a chave de segurança e
          assinará esta ordem.
        </p>
        <button type="button" onClick={aoCancelar}>
          Cancelar
        </button>
        <button type="button" className="perigo" onClick={aoConfirmar}>
          Sim, apagar a máquina
        </button>
      </div>
    </div>
  );
}
