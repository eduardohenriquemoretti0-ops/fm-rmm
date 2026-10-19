import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { TabelaAgentes } from './TabelaAgentes';
import { ConteudoVulns } from './PainelVulns';
import {
  classeSeveridade,
  formatarSaude,
  formatarUpdates,
  formatarVulns,
  maiorSeveridade,
} from './resumos';
import { lerResumoVulns } from '../api/endpoints';
import type { Agente } from '../api/tipos';

function agente(parcial: Partial<Agente>): Agente {
  return {
    id: 'a1', hostname: 'h1', os: 'linux', status: 'aprovado', grupo: 'g', online: true,
    ultimo_contato: null,
    vulnerabilidades: { escaneado: false, escaneado_em: null, total: 0, por_severidade: {} },
    updates: { pendentes: null, reinicio_pendente: null },
    saude: { estavel: null, eventos: null },
    ...parcial,
  };
}

describe('badge de severidade', () => {
  it('escolhe a maior severidade com contagem > 0', () => {
    expect(maiorSeveridade({ LOW: 4, HIGH: 2, MEDIUM: 1, CRITICAL: 0 })).toBe('HIGH');
    expect(maiorSeveridade({ CRITICAL: 1, LOW: 9 })).toBe('CRITICAL');
    expect(maiorSeveridade({})).toBeNull();
  });
  it('severidade hostil cai em classe fixa', () => {
    expect(classeSeveridade('"><script>')).toBe('sev sev-desconhecida');
    expect(classeSeveridade('critical')).toBe('sev sev-critical');
  });
  it('escaneado=false mostra traço; escaneado com 0 não tem badge', () => {
    expect(formatarVulns({ escaneado: false, escaneado_em: null, total: 0, por_severidade: {} }))
      .toEqual({ texto: '—', severidade: null });
    expect(formatarVulns({ escaneado: true, escaneado_em: null, total: 0, por_severidade: {} }))
      .toEqual({ texto: '0', severidade: null });
    expect(formatarVulns({ escaneado: true, escaneado_em: null, total: 3, por_severidade: { HIGH: 1, LOW: 2 } }))
      .toEqual({ texto: '3', severidade: 'HIGH' });
  });
});

describe('updates e saúde formatados', () => {
  it('updates: null vira traço; pendentes + reinício', () => {
    expect(formatarUpdates({ pendentes: null, reinicio_pendente: null }).texto).toBe('—');
    expect(formatarUpdates({ pendentes: 5, reinicio_pendente: true })).toEqual({
      texto: '5', reinicio: true, estado: 'pendente',
    });
    expect(formatarUpdates({ pendentes: 0, reinicio_pendente: false }).estado).toBe('ok');
  });
  it('saúde: estável, instável com N eventos, desconhecido', () => {
    expect(formatarSaude({ estavel: true, eventos: 0 }).texto).toBe('Estável');
    expect(formatarSaude({ estavel: false, eventos: 3 }).texto).toBe('Instável (3 eventos)');
    expect(formatarSaude({ estavel: false, eventos: 1 }).texto).toBe('Instável (1 evento)');
    expect(formatarSaude({ estavel: null, eventos: null }).texto).toBe('—');
  });
});

describe('grid com colunas novas', () => {
  it('renderiza vulns, updates, reinício e saúde', () => {
    const html = renderToStaticMarkup(
      <TabelaAgentes
        agentes={[
          agente({
            vulnerabilidades: { escaneado: true, escaneado_em: null, total: 4, por_severidade: { CRITICAL: 1, LOW: 3 } },
            updates: { pendentes: 7, reinicio_pendente: true },
            saude: { estavel: false, eventos: 2 },
          }),
        ]}
        aoConectar={() => undefined}
      />,
    );
    expect(html).toContain('sev sev-critical');
    expect(html).toContain('Crítica');
    expect(html).toContain('Reinício pendente');
    expect(html).toContain('Instável (2 eventos)');
    expect(html).toContain('saude-instavel');
  });

  it('dado hostil nos novos campos fica escapado e sem elementos injetados', () => {
    const html = renderToStaticMarkup(
      <TabelaAgentes
        agentes={[
          agente({
            hostname: '<img src=x onerror=alert(1)>',
            vulnerabilidades: {
              escaneado: true, escaneado_em: null, total: 1,
              por_severidade: { '"><script>alert(2)</script>': 1 },
            },
          }),
        ]}
        aoConectar={() => undefined}
      />,
    );
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toMatch(/<img/i);
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toContain('alert(2)');
  });

  it('agente sem scan mostra traços', () => {
    const html = renderToStaticMarkup(<TabelaAgentes agentes={[agente({})]} aoConectar={() => undefined} />);
    expect(html).toContain('data-col="vulns">—<');
    expect(html).toContain('data-col="saude" class="saude saude-desconhecido">—<');
  });
});

describe('painel de CVEs', () => {
  const bruto = {
    escaneado: true, escaneado_em: '2026-10-18T10:00:00Z', fonte: 'osv', total: 1,
    por_severidade: { HIGH: 1 },
    vulnerabilidades: [
      { osv_id: 'x', cve_id: 'CVE-2026-1111', pacote: 'openssl', versao: '3.0.1', severidade: 'HIGH', pontuacao: 7.5, fixed_version: '3.0.9', fonte: 'osv' },
      { cve_id: '<b>CVE-HOSTIL</b>', pacote: 'p', versao: '1', severidade: 'MEDIUM', fixed_version: '' },
    ],
    nao_avaliados_alto_risco: [{ pacote: 'foo', versao: '1', motivo: 'sem_fonte' }],
  };
  it('parse do shape: pontuacao ausente vira null', () => {
    const r = lerResumoVulns(bruto);
    expect(r.vulnerabilidades[0]?.pontuacao).toBe(7.5);
    expect(r.vulnerabilidades[1]?.pontuacao).toBeNull();
  });
  it('lista cve/severidade/pontuação/fixed_version e a nota de alto risco', () => {
    const html = renderToStaticMarkup(<ConteudoVulns r={lerResumoVulns(bruto)} />);
    expect(html).toContain('CVE-2026-1111');
    expect(html).toContain('7.5');
    expect(html).toContain('3.0.9');
    expect(html).toContain('1 item de alto risco sem fonte de CVE');
    expect(html).toContain('&lt;b&gt;CVE-HOSTIL&lt;/b&gt;');
    expect(html).not.toMatch(/<b>CVE/);
  });
  it('shape inválido é recusado', () => {
    expect(() => lerResumoVulns({ ...bruto, total: 'x' })).toThrow();
    expect(() => lerResumoVulns({ ...bruto, vulnerabilidades: [{}] })).toThrow();
  });
});
