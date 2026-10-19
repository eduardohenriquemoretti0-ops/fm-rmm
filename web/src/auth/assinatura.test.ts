/**
 * Testes do autenticador contra o VETOR do doc docs/console-assinatura-acao.md
 * (gerado pelo Go: TestVetorCanonicoDocumentado). Ed25519 é determinístico, então
 * a assinatura do vetor tem de sair IGUAL, byte a byte.
 *
 * A chave EXTRAÍVEL existe só aqui (import da seed do vetor). Em produção o
 * par é sempre gerado com extractable:false (Autenticador.gerarPar).
 */
import { webcrypto } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  Autenticador,
  ErroEd25519Indisponivel,
  ErroIntegridade,
  _reiniciarDeteccao,
  assinarAcao,
  b64ParaBytes,
  bytesParaB64,
  bytesParaHex,
  ed25519Disponivel,
  keyIdDe,
  montarRegistroChave,
  sha256,
  type Assinador,
} from './assinatura';
import { jsonString, serializarGrant, serializarJob } from './canonico';

const SEED_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const PUB_B64 = 'A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=';
const KEY_ID = '56475aa75463474c';

const JOB_JSON =
  '{"v":1,"job_id":"job-0123456789abcdef","agent_id":"agt-0001","action":"info","params":{"a":"1","b":"2"},"issued_at":"2026-10-19T12:00:00Z","expires_at":"2026-10-19T13:00:00Z","issuer":"op-joao"}';
const JOB_SHA = '8df364fb508ca9f2601e53b8b86c0aa7e995a1f9141ee4943eee2c9066689ea5';
const JOB_SIG =
  '7uImsymUQOmFO5OTjcMLRnISRRBfhQxabqAIbPb+XY6nk4p8Ktju1m6gaPfSBjnJpTZL3k4ekpE5EfFIUNxNBA==';

const GRANT_JSON =
  '{"v":1,"session_id":"ses-0123456789abcdef","agent_id":"agt-0001","technician":"joao","mode":"view","engine":"screenshot","relay_url":"wss://relay.exemplo:8443/r","relay_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","issued_at":"2026-10-19T12:00:00Z","expires_at":"2026-10-19T12:10:00Z","issuer":"op-joao"}';
const GRANT_SHA = '4a5834875b2093aea1c42597fedf2f8f850f68044a22892896b7da5da333ace4';
const GRANT_SIG =
  'PHu0ceiydCnUJyVTZ85iQqjsec7ZDoX66hne75JTpjBB5Gv1sPfV43NQocIE55L6jvcWD46248VMdWgyYQfhBA==';

const PROVA_OP_JOAO =
  'ZQ1045ka3+2cDB2qhfuSua9cLAxBh+nUXJr81W1lcy+/ZFdNcUQB6e28qiQxClFIpAbsIBsgTsZUr2Oqe97vBA==';

const T0 = new Date('2026-10-19T12:00:00Z');
const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

const job = {
  v: 1 as const,
  job_id: 'job-0123456789abcdef',
  agent_id: 'agt-0001',
  action: 'info',
  params: { b: '2', a: '1' },
  issued_at: T0,
  expires_at: new Date('2026-10-19T13:00:00Z'),
  issuer: 'op-joao',
};
const grant = {
  v: 1 as const,
  session_id: 'ses-0123456789abcdef',
  agent_id: 'agt-0001',
  technician: 'joao',
  mode: 'view' as const,
  engine: 'screenshot' as const,
  relay_url: 'wss://relay.exemplo:8443/r',
  relay_token: 'A'.repeat(40),
  issued_at: T0,
  expires_at: new Date('2026-10-19T12:10:00Z'),
  issuer: 'op-joao',
};

let vetor: Autenticador;

beforeAll(async () => {
  if ((globalThis as { crypto?: unknown }).crypto === undefined) {
    vi.stubGlobal('crypto', webcrypto);
  }
  // PKCS#8 de Ed25519 = prefixo fixo + seed de 32 bytes. EXTRAÍVEL: só no teste.
  const pkcs8 = new Uint8Array([
    ...Buffer.from('302e020100300506032b657004220420', 'hex'),
    ...Buffer.from(SEED_HEX, 'hex'),
  ]);
  const priv = await webcrypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', true, ['sign']);
  const jwk = await webcrypto.subtle.exportKey('jwk', priv);
  const pubRaw = Buffer.from(String(jwk.x), 'base64url');
  const pub = await webcrypto.subtle.importKey('raw', pubRaw, 'Ed25519', true, ['verify']);
  vetor = await Autenticador.dePar(
    { privateKey: priv, publicKey: pub } as CryptoKeyPair,
    { somenteTeste: true },
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  _reiniciarDeteccao();
});

describe('vetor do doc: chave', () => {
  it('pública e key_id batem com o Go', async () => {
    expect(bytesParaB64(vetor.pubRaw)).toBe(PUB_B64);
    expect(vetor.keyId).toBe(KEY_ID);
    expect(await keyIdDe(b64ParaBytes(PUB_B64))).toBe(KEY_ID);
  });
});

describe('vetor do doc: job', () => {
  it('bytes canônicos idênticos (params fora de ordem saem ordenados)', () => {
    expect(new TextDecoder().decode(serializarJob(job))).toBe(JOB_JSON);
  });
  it('SHA-256, assinatura e envelope idênticos', async () => {
    const bytes = serializarJob(job);
    expect(bytesParaHex(await sha256(bytes))).toBe(JOB_SHA);
    const acao = await assinarAcao(vetor, 'job', bytes);
    expect(acao.sig).toBe(JOB_SIG);
    expect(acao.key_id).toBe(KEY_ID);
    expect(acao.tipo).toBe('job');
    // payload = base64 dos BYTES (não do objeto)
    expect(acao.payload).toBe(Buffer.from(JOB_JSON, 'utf8').toString('base64'));
  });
});

describe('vetor do doc: grant', () => {
  it('bytes canônicos idênticos', () => {
    expect(new TextDecoder().decode(serializarGrant(grant))).toBe(GRANT_JSON);
  });
  it('SHA-256, assinatura e envelope idênticos', async () => {
    const bytes = serializarGrant(grant);
    expect(bytesParaHex(await sha256(bytes))).toBe(GRANT_SHA);
    const acao = await assinarAcao(vetor, 'grant', bytes);
    expect(acao.sig).toBe(GRANT_SIG);
    expect(acao.key_id).toBe(KEY_ID);
    expect(acao.payload).toBe(Buffer.from(GRANT_JSON, 'utf8').toString('base64'));
  });
});

describe('prova de posse do cadastro da chave', () => {
  it('assinatura sobre "fmrmm-signing-pub-v1\\n<op>\\n<pub>" idêntica ao vetor', async () => {
    const r = await montarRegistroChave(vetor, 'op-joao');
    expect(r.signing_pub).toBe(PUB_B64);
    expect(r.prova).toBe(PROVA_OP_JOAO);
  });
});

describe('serializador espelha o encoding/json do Go', () => {
  it('omite params vazio e media_secret vazio', () => {
    const j = new TextDecoder().decode(serializarJob({ ...job, params: {} }));
    expect(j).not.toContain('params');
    const g = new TextDecoder().decode(serializarGrant({ ...grant, media_secret: '' }));
    expect(g).not.toContain('media_secret');
  });
  it('media_secret entra entre engine e relay_url', () => {
    const g = new TextDecoder().decode(
      serializarGrant({ ...grant, engine: 'rustdesk', media_secret: 'seg' }),
    );
    expect(g).toContain('"engine":"rustdesk","media_secret":"seg","relay_url"');
  });
  it('escapa < > & U+2028 U+2029 em minúsculas e não escapa /', () => {
    expect(jsonString('a<b>c&d e f/g')).toBe(
      '"a\\u003cb\\u003ec\\u0026d\\u2028e\\u2029f/g"',
    );
  });
  it('escapes de controle, aspas e barra invertida', () => {
    expect(jsonString('"\\\n\r\t\u0001')).toBe('"\\"\\\\\\n\\r\\t\\u0001"');
  });
  it('relay_url com & sai escapado nos bytes do grant', () => {
    const g = new TextDecoder().decode(
      serializarGrant({ ...grant, relay_url: 'wss://x/r?a=1&b=2' }),
    );
    expect(g).toContain('wss://x/r?a=1\\u0026b=2');
  });
  it('trunca fração de segundo e usa Z', () => {
    const j = new TextDecoder().decode(
      serializarJob({ ...job, issued_at: new Date('2026-10-19T12:00:00.987Z') }),
    );
    expect(j).toContain('"issued_at":"2026-10-19T12:00:00Z"');
  });
  it('rejeita nonce inválido e validade acima do máximo', () => {
    expect(() => serializarJob({ ...job, job_id: 'curto' })).toThrow();
    expect(() =>
      serializarGrant({ ...grant, expires_at: new Date('2026-10-19T12:31:00Z') }),
    ).toThrow();
  });
});

describe('integridade ida-e-volta', () => {
  it('payload adulterado depois do h1 anunciado ABORTA a assinatura', async () => {
    const original = serializarJob(job);
    const h1 = bytesParaHex(await sha256(original));
    const adulterado = enc(JOB_JSON.replace('"agt-0001"', '"agt-0666"'));
    await expect(vetor.assinar(adulterado, h1)).rejects.toBeInstanceOf(ErroIntegridade);
  });

  it('assinatura que não confere na volta ABORTA o envio', async () => {
    const falso: Assinador = {
      pubRaw: vetor.pubRaw,
      keyId: vetor.keyId,
      // devolve assinatura de OUTRO conteúdo (autenticador comprometido)
      assinar: async () => b64ParaBytes(JOB_SIG),
      verificar: (bytes, sig) => vetor.verificar(bytes, sig),
    };
    const outro = serializarJob({ ...job, action: 'outra' });
    await expect(assinarAcao(falso, 'job', outro)).rejects.toBeInstanceOf(ErroIntegridade);
  });

  it('bytes não canônicos (espaço extra / params vazio / campo extra) abortam antes de assinar', async () => {
    const espaco = JOB_JSON.replace('"v":1,', '"v": 1,');
    await expect(assinarAcao(vetor, 'job', enc(espaco))).rejects.toBeInstanceOf(ErroIntegridade);
    const vazio = JOB_JSON.replace(',"params":{"a":"1","b":"2"}', ',"params":{}');
    await expect(assinarAcao(vetor, 'job', enc(vazio))).rejects.toThrow();
    const extra = JOB_JSON.replace('"v":1,', '"v":1,"extra":1,');
    await expect(assinarAcao(vetor, 'job', enc(extra))).rejects.toThrow();
    const ordem = JOB_JSON.replace('"job_id":"job-0123456789abcdef","agent_id":"agt-0001"', '"agent_id":"agt-0001","job_id":"job-0123456789abcdef"');
    await expect(assinarAcao(vetor, 'job', enc(ordem))).rejects.toBeInstanceOf(ErroIntegridade);
  });
});

describe('chave de produção: não exportável + feature-detect', () => {
  it('gerar() produz privada extractable:false e exportKey falha', async () => {
    const par = await Autenticador.gerarPar();
    expect(par.privateKey.extractable).toBe(false);
    await expect(webcrypto.subtle.exportKey('pkcs8', par.privateKey)).rejects.toThrow();
    await expect(webcrypto.subtle.exportKey('jwk', par.privateKey)).rejects.toThrow();
    const aut = await Autenticador.dePar(par);
    expect(aut.keyId).toMatch(/^[0-9a-f]{16}$/);
    const acao = await assinarAcao(aut, 'job', serializarJob(job));
    expect(b64ParaBytes(acao.sig)).toHaveLength(64);
  });

  it('recusa par com privada exportável (fora do modo de teste)', async () => {
    const pkcs8 = new Uint8Array([
      ...Buffer.from('302e020100300506032b657004220420', 'hex'),
      ...Buffer.from(SEED_HEX, 'hex'),
    ]);
    const priv = await webcrypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', true, ['sign']);
    await expect(
      Autenticador.dePar({ privateKey: priv, publicKey: priv } as CryptoKeyPair),
    ).rejects.toThrow(/exportável/);
  });

  it('sem Ed25519 no SubtleCrypto: flag false + falha clara, sem fallback', async () => {
    const sub = webcrypto.subtle;
    vi.spyOn(sub, 'generateKey').mockRejectedValue(new DOMException('x', 'NotSupportedError'));
    await expect(ed25519Disponivel()).resolves.toBe(false);
    const e = await Autenticador.gerar().catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ErroEd25519Indisponivel);
    expect((e as Error).message).toMatch(/Ed25519/);
  });
});
