import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { TabelaAgentes } from './TabelaAgentes';
import type { Agente } from '../api/tipos';

// Dados hostis vindos do agente (inventário controlado por terceiros) devem
// aparecer como TEXTO escapado, nunca como marcação executável.
const hostil: Agente = {
  id: '<script>alert(1)</script>',
  hostname: '<img src=x onerror=alert(2)>',
  os: '"><svg onload=alert(3)>',
  online: true,
  ultimo_contato: 'javascript:alert(4)',
};

describe('TabelaAgentes — escape automático', () => {
  const html = renderToStaticMarkup(
    <TabelaAgentes agentes={[hostil]} aoConectar={() => undefined} />,
  );

  it('escapa tags do hostname, id e SO', () => {
    expect(html).toContain('&lt;img src=x onerror=alert(2)&gt;');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('&quot;&gt;&lt;svg onload=alert(3)&gt;');
  });

  it('não gera nenhum elemento a partir do dado do agente', () => {
    expect(html).not.toMatch(/<img/i);
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/<svg/i);
  });

  it('último contato inválido não ecoa o texto cru', () => {
    expect(html).not.toContain('javascript:alert(4)');
  });
});
