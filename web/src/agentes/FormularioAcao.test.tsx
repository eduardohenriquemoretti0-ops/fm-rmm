import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { FormularioAcao, DialogoDestrutivo } from './FormularioAcao';
import { FormularioBmc, acoesDeEnergia } from './PainelBmc';
import { camposDaAcao, estadoEnvio } from '../acoes/formulario';
import { FORM_BMC_VAZIO } from '../acoes/bmc';
import type { AcaoDisponivel } from '../api/tipos';

const agente = { id: 'agt-0001', os: 'windows' };
const listas = {
  software: [{ id: 'firefox', nome: 'Firefox', gerenciador: 'winget' }],
  scripts: [{ id: 'limpa-temp', nome: 'Limpa', versao: '1.0.0', interprete: 'powershell' }],
};
const wipe: AcaoDisponivel = {
  nome: 'wipe_remoto', rotulo: 'DESTRUTIVO', origem: 'agente', rota: '/api/acoes', destrutiva: true,
  exige_step_up: true, so: ['windows'],
  params: [
    { nome: 'confirmacao', rotulo: 'Confirmação', obrigatorio: true, tipo: 'confirmacao_destrutiva', formato: 'WIPE-{agent_id}' },
    { nome: 'motivo', rotulo: 'Motivo', obrigatorio: true, tipo: 'lista', valores_por_so: { windows: ['perda', 'roubo'] } },
  ],
};
const instalar: AcaoDisponivel = {
  nome: 'instalar_pacote', rotulo: 'Instalar', origem: 'agente', rota: '/api/acoes', destrutiva: false,
  exige_step_up: true, so: ['windows'],
  params: [{ nome: 'item_id', rotulo: 'Item', obrigatorio: true, tipo: 'item_catalogo_software' }],
};

function render(acao: AcaoDisponivel, valores: Record<string, string>, dialogo = false): string {
  const campos = camposDaAcao(acao, agente, listas, valores);
  return renderToStaticMarkup(
    <FormularioAcao
      acao={acao}
      campos={campos}
      valores={valores}
      estado={estadoEnvio(acao, campos, valores, dialogo)}
      ocupado={false}
      aoMudar={() => undefined}
      aoSolicitar={() => undefined}
    />,
  );
}

describe('FormularioAcao (HTML renderizado)', () => {
  it('wipe: aviso vermelho e botão desabilitado até digitar WIPE-<id> + motivo', () => {
    const vazio = render(wipe, {});
    expect(vazio).toContain('acao-destrutiva');
    expect(vazio).toContain('role="alert"');
    expect(vazio).toContain('WIPE-agt-0001');
    expect(vazio).toMatch(/<button[^>]*type="submit"[^>]*disabled/);
    const ok = render(wipe, { confirmacao: 'WIPE-agt-0001', motivo: 'perda' });
    expect(ok).not.toMatch(/<button[^>]*type="submit"[^>]*disabled/);
  });

  it('instalar: select com ids do catálogo, sem input de texto nem textarea', () => {
    const h = render(instalar, {});
    expect(h).toContain('<select');
    expect(h).toContain('value="firefox"');
    expect(h).not.toMatch(/<input/);
    expect(h).not.toMatch(/<textarea/);
    expect(h).not.toMatch(/pkg_id/);
  });

  it('dados hostis do servidor/agente saem escapados', () => {
    const hostil = { ...instalar, rotulo: '<img src=x onerror=alert(1)>' };
    const h = render(hostil, {});
    expect(h).not.toMatch(/<img/);
    expect(h).toContain('&lt;img');
  });

  it('diálogo explícito diz que apaga a máquina', () => {
    const h = renderToStaticMarkup(
      <DialogoDestrutivo agente="h (agt-0001)" aoConfirmar={() => undefined} aoCancelar={() => undefined} />,
    );
    expect(h).toContain('role="alertdialog"');
    expect(h).toContain('Isto apaga a máquina');
  });
});

describe('FormularioBmc (HTML renderizado)', () => {
  const acao: AcaoDisponivel = {
    nome: 'bmc_power', rotulo: 'BMC', origem: 'bmc', rota: '/api/bmc/power', destrutiva: false,
    exige_step_up: true,
    params: [{ nome: 'acao', rotulo: 'ação', obrigatorio: true, tipo: 'lista', valores_por_so: { bmc: ['On', 'ForceOff'] } }],
  };
  it('senha é type=password, sem autopreenchimento; ações vêm da lista do servidor', () => {
    const h = renderToStaticMarkup(
      <FormularioBmc form={FORM_BMC_VAZIO} acoesEnergia={acoesDeEnergia(acao)} ocupado={false}
        aoMudar={() => undefined} aoEnviar={() => undefined} aoConsultar={() => undefined} />,
    );
    expect(h).toMatch(/<input[^>]*type="password"[^>]*name="senha"/);
    expect(h).toMatch(/type="password"[^>]*autoComplete="new-password"/); // (React estático emite camelCase)
    expect(h).toContain('value="ForceOff"');
  });
});
