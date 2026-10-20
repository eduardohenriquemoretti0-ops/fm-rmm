import { describe, expect, it } from 'vitest';
import type { AcaoDisponivel } from '../api/tipos';
import {
  acoesDoAgente,
  camposDaAcao,
  campoValido,
  confirmacaoEsperada,
  estadoEnvio,
  montarParams,
  type ListasFormulario,
} from './formulario';

const listas: ListasFormulario = {
  software: [
    { id: 'firefox', nome: 'Firefox', gerenciador: 'winget' },
    { id: 'vlc', nome: 'VLC', gerenciador: 'apt' },
  ],
  scripts: [
    { id: 'limpa-temp', nome: 'Limpa temp', versao: '1.0.0', interprete: 'powershell' },
    { id: 'limpa-temp', nome: 'Limpa temp', versao: '1.1.0', interprete: 'powershell' },
    { id: 'rotaciona-log', nome: 'Rotaciona', versao: '2.0.0', interprete: 'sh' },
  ],
};
const agente = { id: 'agt-0001', os: 'windows' };

const wol: AcaoDisponivel = {
  nome: 'wake_on_lan', rotulo: 'Acordar', origem: 'agente', rota: '/api/acoes', destrutiva: false,
  exige_step_up: true, so: ['linux', 'windows'],
  params: [{ nome: 'mac', rotulo: 'MAC do alvo', obrigatorio: true, tipo: 'texto' }],
};
const instalar: AcaoDisponivel = {
  nome: 'instalar_pacote', rotulo: 'Instalar', origem: 'agente', rota: '/api/acoes', destrutiva: false,
  exige_step_up: true, so: ['windows'],
  params: [{ nome: 'item_id', rotulo: 'Item', obrigatorio: true, tipo: 'item_catalogo_software' }],
};
const script: AcaoDisponivel = {
  nome: 'rodar_script', rotulo: 'Rodar script', origem: 'agente', rota: '/api/acoes', destrutiva: false,
  exige_step_up: true, so: ['windows', 'linux'],
  params: [
    { nome: 'script_id', rotulo: 'Script', obrigatorio: true, tipo: 'script_biblioteca_id' },
    { nome: 'versao', rotulo: 'Versão', obrigatorio: true, tipo: 'script_biblioteca_versao' },
  ],
};
export const wipe: AcaoDisponivel = {
  nome: 'wipe_remoto', rotulo: 'DESTRUTIVO', origem: 'agente', rota: '/api/acoes', destrutiva: true,
  exige_step_up: true, so: ['linux', 'windows'],
  params: [
    { nome: 'confirmacao', rotulo: 'Confirmação', obrigatorio: true, tipo: 'confirmacao_destrutiva', formato: 'WIPE-{agent_id}' },
    { nome: 'motivo', rotulo: 'Motivo', obrigatorio: true, tipo: 'lista', valores_por_so: { windows: ['perda', 'roubo'], linux: ['perda', 'roubo'] } },
  ],
};
const bmc: AcaoDisponivel = {
  nome: 'bmc_power', rotulo: 'BMC', origem: 'bmc', rota: '/api/bmc/power', destrutiva: false,
  exige_step_up: true, params: [],
};

describe('forma do formulário por tipo de param', () => {
  it('texto -> input de texto', () => {
    const [c] = camposDaAcao(wol, agente, listas);
    expect(c).toMatchObject({ tipo: 'texto', nome: 'mac', obrigatorio: true });
  });

  it('lista -> select com valores_por_so do SO do agente', () => {
    const c = camposDaAcao(wipe, agente, listas).find((x) => x.nome === 'motivo');
    expect(c).toMatchObject({ tipo: 'select', fonte: 'lista' });
    expect(c?.tipo === 'select' && c.opcoes.map((o) => o.valor)).toEqual(['perda', 'roubo']);
    const sem = camposDaAcao(wipe, { id: 'x', os: 'darwin' }, listas).find((x) => x.nome === 'motivo');
    expect(sem?.tipo === 'select' && sem.opcoes).toEqual([]);
  });

  it('confirmacao_destrutiva -> campo com texto esperado WIPE-<id>', () => {
    const c = camposDaAcao(wipe, agente, listas).find((x) => x.nome === 'confirmacao');
    expect(c).toMatchObject({ tipo: 'confirmacao', esperado: 'WIPE-agt-0001' });
    expect(confirmacaoEsperada('WIPE-{agent_id}', 'abc')).toBe('WIPE-abc');
  });
});

describe('dropdowns consomem catálogo e biblioteca', () => {
  it('item_catalogo_software lista só ids do catálogo', () => {
    const [c] = camposDaAcao(instalar, agente, listas);
    expect(c).toMatchObject({ tipo: 'select', fonte: 'catalogo_software' });
    expect(c?.tipo === 'select' && c.opcoes.map((o) => o.valor)).toEqual(['firefox', 'vlc']);
  });

  it('script_biblioteca_id deduplica e versao depende do script escolhido', () => {
    const [id, ver0] = camposDaAcao(script, agente, listas);
    expect(id?.tipo === 'select' && id.opcoes.map((o) => o.valor)).toEqual(['limpa-temp', 'rotaciona-log']);
    expect(ver0?.tipo === 'select' && ver0.opcoes).toEqual([]);
    const [, ver] = camposDaAcao(script, agente, listas, { script_id: 'limpa-temp' });
    expect(ver?.tipo === 'select' && ver.opcoes.map((o) => o.valor)).toEqual(['1.0.0', '1.1.0']);
  });

  it('valor fora das opções oferecidas é inválido (nada de id digitado)', () => {
    const [c] = camposDaAcao(instalar, agente, listas);
    expect(c && campoValido(c, 'firefox')).toBe(true);
    expect(c && campoValido(c, 'pkg.arbitrario')).toBe(false);
  });
});

describe('nenhum pkg_id/corpo/comando digitável', () => {
  it('instalar/rodar_script só geram selects; nenhum campo de texto', () => {
    for (const a of [instalar, script]) {
      const cs = camposDaAcao(a, agente, listas, { script_id: 'limpa-temp' });
      expect(cs.every((c) => c.tipo === 'select')).toBe(true);
      expect(cs.map((c) => c.nome)).not.toContain('pkg_id');
      expect(cs.map((c) => c.nome)).not.toContain('corpo');
    }
  });

  it('params montados carregam só os ids escolhidos', () => {
    const cs = camposDaAcao(script, agente, listas, { script_id: 'limpa-temp' });
    expect(montarParams(cs, { script_id: 'limpa-temp', versao: '1.1.0' })).toEqual({
      script_id: 'limpa-temp',
      versao: '1.1.0',
    });
  });
});

describe('filtro por SO', () => {
  it('só ações de origem agente que o SO suporta; BMC fica de fora', () => {
    const r = acoesDoAgente([wol, instalar, bmc, wipe], { os: 'linux' });
    expect(r.map((a) => a.nome)).toEqual(['wake_on_lan', 'wipe_remoto']);
  });
});

describe('wipe: exige WIPE-<id> + motivo + diálogo antes de habilitar', () => {
  const campos = camposDaAcao(wipe, agente, listas);
  const ok = { confirmacao: 'WIPE-agt-0001', motivo: 'roubo' };

  it('sem nada digitado: bloqueado', () => {
    const e = estadoEnvio(wipe, campos, {}, false);
    expect(e.podeSolicitar).toBe(false);
    expect(e.podeEnviar).toBe(false);
  });
  it('confirmação errada (ou de outro agente) bloqueia', () => {
    for (const c of ['wipe-agt-0001', 'WIPE-agt-0002', 'WIPE-agt-0001 ', '']) {
      expect(estadoEnvio(wipe, campos, { ...ok, confirmacao: c }, true).podeEnviar).toBe(false);
    }
  });
  it('sem motivo ou motivo fora da lista bloqueia', () => {
    expect(estadoEnvio(wipe, campos, { confirmacao: 'WIPE-agt-0001' }, true).podeEnviar).toBe(false);
    expect(estadoEnvio(wipe, campos, { ...ok, motivo: 'tedio' }, true).podeEnviar).toBe(false);
  });
  it('tudo certo mas sem o diálogo: pode abrir o diálogo, não pode enviar', () => {
    const e = estadoEnvio(wipe, campos, ok, false);
    expect(e.podeSolicitar).toBe(true);
    expect(e.podeEnviar).toBe(false);
  });
  it('com diálogo confirmado: envia', () => {
    expect(estadoEnvio(wipe, campos, ok, true).podeEnviar).toBe(true);
  });
  it('destrutiva sem campo de confirmação falha fechado', () => {
    const semConf = { ...wipe, params: wipe.params.filter((p) => p.nome === 'motivo') };
    const cs = camposDaAcao(semConf, agente, listas);
    expect(estadoEnvio(semConf, cs, { motivo: 'perda' }, true).podeEnviar).toBe(false);
  });
});
