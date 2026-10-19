import { afterEach, describe, expect, it, vi } from 'vitest';
import { registrarCredencial } from './registro';
import { mensagemErroRegistro } from './Registro';
import { ErroApi } from '../api/cliente';

function json(corpo: unknown, status = 200): Response {
  return new Response(JSON.stringify(corpo), { status, headers: { 'Content-Type': 'application/json' } });
}

const opcoes = {
  publicKey: {
    challenge: 'AQID',
    rp: { id: 'rmm.exemplo.com', name: 'FM-RMM' },
    user: { id: 'b3A', name: 'op-a', displayName: 'Op A' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60000,
    excludeCredentials: [{ type: 'public-key', id: 'AAEC' }],
    authenticatorSelection: { userVerification: 'required' },
    attestation: 'none',
  },
};

class FakeAttestation {
  clientDataJSON = new Uint8Array([1, 2]).buffer;
  attestationObject = new Uint8Array([3, 4]).buffer;
  getTransports() { return ['usb']; }
}
class FakePKC {
  id = 'cred-id';
  rawId = new Uint8Array([9, 9]).buffer;
  response = new FakeAttestation();
}

afterEach(() => vi.unstubAllGlobals());

describe('fluxo de registro WebAuthn', () => {
  it('chama /inicio, navigator.credentials.create e /fim com cerimônia e credencial', async () => {
    const create = vi.fn().mockResolvedValue(new FakePKC());
    vi.stubGlobal('window', { isSecureContext: true });
    vi.stubGlobal('PublicKeyCredential', FakePKC);
    vi.stubGlobal('AuthenticatorAttestationResponse', FakeAttestation);
    vi.stubGlobal('navigator', { credentials: { create } });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ cerimonia: 'cer-1', opcoes }))
      .mockResolvedValueOnce(json({ credencial: 'abc' }, 201));
    vi.stubGlobal('fetch', fetchMock);

    await expect(registrarCredencial()).resolves.toBe('abc');

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [u1, i1] = fetchMock.mock.calls[0] as [string, RequestInit];
    const [u2, i2] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(u1).toBe('/api/registro/inicio');
    expect(i1.method).toBe('POST');
    expect(u2).toBe('/api/registro/fim');
    expect(new Headers(i2.headers).get('X-FMRMM-Cerimonia')).toBe('cer-1');
    const corpo = JSON.parse(i2.body as string);
    expect(corpo.id).toBe('cred-id');
    expect(corpo.response.attestationObject).toBe('AwQ');
    expect(corpo.response.clientDataJSON).toBe('AQI');

    const arg = create.mock.calls[0]?.[0].publicKey;
    expect(arg.challenge).toBeInstanceOf(Uint8Array);
    expect(arg.authenticatorSelection.userVerification).toBe('required');
    expect(arg.attestation).toBe('none');
    expect(arg.excludeCredentials).toHaveLength(1);
  });

  it('suporta registrar duas chaves em sequência (duas cerimônias)', async () => {
    vi.stubGlobal('window', { isSecureContext: true });
    vi.stubGlobal('PublicKeyCredential', FakePKC);
    vi.stubGlobal('AuthenticatorAttestationResponse', FakeAttestation);
    vi.stubGlobal('navigator', { credentials: { create: vi.fn().mockResolvedValue(new FakePKC()) } });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ cerimonia: 'c1', opcoes }))
      .mockResolvedValueOnce(json({ credencial: 'k1' }, 201))
      .mockResolvedValueOnce(json({ cerimonia: 'c2', opcoes }))
      .mockResolvedValueOnce(json({ credencial: 'k2' }, 201));
    vi.stubGlobal('fetch', fetchMock);
    expect(await registrarCredencial()).toBe('k1');
    expect(await registrarCredencial()).toBe('k2');
    const urls = fetchMock.mock.calls.map((c) => c[0]);
    expect(urls).toEqual([
      '/api/registro/inicio', '/api/registro/fim', '/api/registro/inicio', '/api/registro/fim',
    ]);
  });

  it('não chama /fim se o autenticador recusar', async () => {
    vi.stubGlobal('window', { isSecureContext: true });
    vi.stubGlobal('PublicKeyCredential', FakePKC);
    vi.stubGlobal('navigator', { credentials: { create: vi.fn().mockRejectedValue(new DOMException('x', 'NotAllowedError')) } });
    const fetchMock = vi.fn().mockResolvedValueOnce(json({ cerimonia: 'c', opcoes }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(registrarCredencial()).rejects.toBeInstanceOf(DOMException);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('mensagens de erro: 422 (chave sincronizável) e 403 (não pendente)', () => {
    expect(mensagemErroRegistro(new ErroApi(422, 'x'))).toContain('chave física');
    expect(mensagemErroRegistro(new ErroApi(403, 'x'))).toContain('não está pendente');
  });
});
