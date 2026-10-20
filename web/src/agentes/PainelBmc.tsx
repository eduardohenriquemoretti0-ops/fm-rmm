/**
 * Controle de energia por BMC (só renderizado se /api/acoes-disponiveis trouxer
 * a ação de origem `bmc`). A credencial é digitada na hora, vive só neste
 * estado React, é APAGADA do estado ANTES do envio e nunca toca em storage.
 */
import { useState } from 'react';
import type { AcaoDisponivel } from '../api/tipos';
import {
  aposEnvio,
  executarBmc,
  FORM_BMC_VAZIO,
  validarFormBmc,
  type FormBmc,
} from '../acoes/bmc';

export function acoesDeEnergia(acao: AcaoDisponivel): string[] {
  const p = acao.params.find((x) => x.nome === 'acao');
  return [...(p?.valores_por_so?.['bmc'] ?? [])];
}

export function FormularioBmc({
  form,
  acoesEnergia,
  ocupado,
  aoMudar,
  aoEnviar,
  aoConsultar,
}: {
  readonly form: FormBmc;
  readonly acoesEnergia: ReadonlyArray<string>;
  readonly ocupado: boolean;
  readonly aoMudar: (campo: keyof FormBmc, valor: string) => void;
  readonly aoEnviar: () => void;
  readonly aoConsultar: () => void;
}) {
  const campo = (
    nome: keyof FormBmc,
    rotulo: string,
    tipo: 'text' | 'password' = 'text',
  ) => (
    <div className="campo">
      <label htmlFor={`bmc-${nome}`}>{rotulo}</label>
      <input
        id={`bmc-${nome}`}
        name={nome}
        type={tipo}
        value={form[nome]}
        maxLength={nome === 'usuario' || nome === 'senha' ? 256 : 253}
        // credencial: sem autopreenchimento/gerenciador de senhas do navegador
        autoComplete={tipo === 'password' ? 'new-password' : 'off'}
        spellCheck={false}
        disabled={ocupado}
        onChange={(e) => aoMudar(nome, e.target.value)}
      />
    </div>
  );
  return (
    <form
      className="acao-form"
      data-acao="bmc_power"
      onSubmit={(e) => {
        e.preventDefault();
        if (!ocupado) aoEnviar();
      }}
    >
      {campo('host', 'Host ou IP do BMC *')}
      {campo('porta', 'Porta (padrão 443)')}
      {campo('system_id', 'ID do sistema Redfish')}
      <div className="campo">
        <label htmlFor="bmc-acao">Ação de energia *</label>
        <select
          id="bmc-acao"
          name="acao"
          value={form.acao}
          disabled={ocupado}
          onChange={(e) => aoMudar('acao', e.target.value)}
        >
          <option value="">— escolha —</option>
          {acoesEnergia.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
      </div>
      {campo('usuario', 'Usuário do BMC *')}
      {campo('senha', 'Senha do BMC *', 'password')}
      <small>A credencial é usada só nesta ação e não é guardada.</small>
      <button type="submit" disabled={ocupado}>
        Enviar ação de energia
      </button>
      <button type="button" disabled={ocupado} onClick={aoConsultar}>
        Consultar estado
      </button>
    </form>
  );
}

export function PainelBmc({ acao }: { readonly acao: AcaoDisponivel }) {
  const [form, setForm] = useState<FormBmc>(FORM_BMC_VAZIO);
  const [ocupado, setOcupado] = useState(false);
  const [resultado, setResultado] = useState<{ ok: boolean; mensagem: string } | null>(null);
  const energia = acoesDeEnergia(acao);

  async function rodar(rota: 'power' | 'status'): Promise<void> {
    if (ocupado) return;
    // status não usa `acao`; reaproveita a validação com a 1ª ação só para a forma
    const v = validarFormBmc(rota === 'status' ? { ...form, acao: energia[0] ?? '' } : form, energia);
    if (!v.ok) {
      setResultado({ ok: false, mensagem: v.erro });
      return;
    }
    // A credencial sai do estado AGORA (antes de qualquer await). `v.corpo` é
    // variável local, descartada ao fim da função.
    setForm(aposEnvio(form));
    setOcupado(true);
    setResultado(null);
    try {
      const r = await executarBmc(rota, v.corpo);
      setResultado({ ok: r.ok, mensagem: r.mensagem });
    } finally {
      setOcupado(false);
    }
  }

  return (
    <section className="painel-acoes" aria-label="Controle de energia por BMC">
      <h3>BMC — controle de energia</h3>
      <FormularioBmc
        form={form}
        acoesEnergia={energia}
        ocupado={ocupado}
        aoMudar={(c, val) => setForm((f) => ({ ...f, [c]: val }))}
        aoEnviar={() => void rodar('power')}
        aoConsultar={() => void rodar('status')}
      />
      {resultado !== null && (
        <p role={resultado.ok ? 'status' : 'alert'} className={resultado.ok ? undefined : 'erro'}>
          {resultado.mensagem}
        </p>
      )}
    </section>
  );
}
