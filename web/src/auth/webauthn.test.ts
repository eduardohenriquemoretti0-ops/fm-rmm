import { describe, expect, it } from 'vitest';
import {
  base64urlParaBytes,
  bytesParaBase64url,
  ErroWebAuthn,
  mensagemErroWebAuthn,
  paraOpcoesRequisicao,
} from './webauthn';
import type { OpcoesAsercaoJSON } from '../api/tipos';

const opcoesBase = (): OpcoesAsercaoJSON => ({
  publicKey: {
    challenge: bytesParaBase64url(new Uint8Array([1, 2, 3, 250, 251, 252])),
    timeout: 300_000,
    rpId: 'console.exemplo.local',
    allowCredentials: [{ type: 'public-key', id: bytesParaBase64url(new Uint8Array([9, 8, 7])) }],
  },
});

describe('base64url', () => {
  it('ida e volta preserva os bytes (incluindo +/ convertidos para -_)', () => {
    const original = new Uint8Array([0xfb, 0xff, 0xbf, 0x00, 0x7f]);
    const txt = bytesParaBase64url(original);
    expect(txt).not.toMatch(/[+/=]/);
    expect(Array.from(base64urlParaBytes(txt))).toEqual(Array.from(original));
  });

  it('recusa caracteres fora do alfabeto base64url', () => {
    expect(() => base64urlParaBytes('abc+')).toThrow(ErroWebAuthn);
    expect(() => base64urlParaBytes('ab c')).toThrow(ErroWebAuthn);
    expect(() => base64urlParaBytes('a=')).toThrow(ErroWebAuthn);
  });

  it('recusa comprimento inválido (resto 1 em módulo 4)', () => {
    expect(() => base64urlParaBytes('abcde')).toThrow(ErroWebAuthn);
  });
});

describe('paraOpcoesRequisicao', () => {
  it('converte challenge e allowCredentials em bytes e aplica userVerification required por padrão', () => {
    const o = paraOpcoesRequisicao(opcoesBase());
    expect(Array.from(o.challenge as Uint8Array)).toEqual([1, 2, 3, 250, 251, 252]);
    expect(o.userVerification).toBe('required');
    expect(o.rpId).toBe('console.exemplo.local');
    const primeiro = o.allowCredentials?.[0];
    expect(primeiro?.type).toBe('public-key');
    expect(Array.from(primeiro?.id as Uint8Array)).toEqual([9, 8, 7]);
  });

  it('limita o timeout a 120 s mesmo que o servidor mande mais', () => {
    expect(paraOpcoesRequisicao(opcoesBase()).timeout).toBe(120_000);
  });

  it('FAIL-CLOSED: sem allowCredentials o login é recusado', () => {
    const semCred = opcoesBase();
    const sem: OpcoesAsercaoJSON = { publicKey: { challenge: semCred.publicKey.challenge } };
    expect(() => paraOpcoesRequisicao(sem)).toThrow(ErroWebAuthn);
    const vazio: OpcoesAsercaoJSON = {
      publicKey: { challenge: semCred.publicKey.challenge, allowCredentials: [] },
    };
    expect(() => paraOpcoesRequisicao(vazio)).toThrow(ErroWebAuthn);
  });
});

describe('mensagemErroWebAuthn', () => {
  it('cancelamento do autenticador vira mensagem própria', () => {
    const erro = new DOMException('cancelado', 'NotAllowedError');
    expect(mensagemErroWebAuthn(erro)).toContain('cancelada');
  });

  it('erros desconhecidos não vazam detalhe técnico', () => {
    expect(mensagemErroWebAuthn(new Error('segredo: 0xDEADBEEF'))).not.toContain('0xDEADBEEF');
  });
});
