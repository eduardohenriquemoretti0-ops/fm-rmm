/**
 * Persistência do par de chaves do operador no IndexedDB.
 *
 * O IndexedDB guarda o objeto `CryptoKey` por structured clone: a chave privada
 * continua NÃO exportável (o JS nunca vê os bytes). Sem isso a chave se perderia
 * a cada recarga. Um armazém por operador (chave = id do operador).
 */
import { Autenticador, ErroAssinatura } from './assinatura';

const BANCO = 'fmrmm-assinatura';
const LOJA = 'chaves';

export interface ArmazemChaves {
  ler(operadorId: string): Promise<CryptoKeyPair | null>;
  gravar(operadorId: string, par: CryptoKeyPair): Promise<void>;
  remover(operadorId: string): Promise<void>;
}

function abrir(): Promise<IDBDatabase> {
  return new Promise((ok, falha) => {
    if (typeof indexedDB === 'undefined') {
      falha(new ErroAssinatura('IndexedDB indisponível neste navegador.'));
      return;
    }
    const req = indexedDB.open(BANCO, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(LOJA);
    req.onsuccess = () => ok(req.result);
    req.onerror = () => falha(new ErroAssinatura('Falha ao abrir o armazém de chaves.'));
  });
}

function pedido<T>(db: IDBDatabase, modo: IDBTransactionMode, f: (l: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((ok, falha) => {
    const req = f(db.transaction(LOJA, modo).objectStore(LOJA));
    req.onsuccess = () => ok(req.result);
    req.onerror = () => falha(new ErroAssinatura('Falha no armazém de chaves.'));
  });
}

export const armazemIndexedDB: ArmazemChaves = {
  async remover(operadorId) {
    const db = await abrir();
    try {
      await pedido(db, 'readwrite', (l) => l.delete(operadorId));
    } finally {
      db.close();
    }
  },
  async ler(operadorId) {
    const db = await abrir();
    try {
      const v = await pedido<unknown>(db, 'readonly', (l) => l.get(operadorId));
      if (v === undefined) return null;
      const par = v as Partial<CryptoKeyPair>;
      if (!par.privateKey || !par.publicKey) return null;
      return { privateKey: par.privateKey, publicKey: par.publicKey };
    } finally {
      db.close();
    }
  },
  async gravar(operadorId, par) {
    const db = await abrir();
    try {
      await pedido(db, 'readwrite', (l) => l.put(par, operadorId));
    } finally {
      db.close();
    }
  },
};

/** Autenticador salvo do operador, ou null se ainda não há chave neste navegador. */
export async function carregarAutenticador(
  operadorId: string,
  armazem: ArmazemChaves = armazemIndexedDB,
): Promise<Autenticador | null> {
  const par = await armazem.ler(operadorId);
  return par === null ? null : Autenticador.dePar(par);
}

/**
 * Gera o par (privada não exportável) e grava. Recusa sobrescrever uma chave já
 * existente: trocar a chave é decisão do admin, fora de banda.
 */
export async function gerarEGuardarAutenticador(
  operadorId: string,
  armazem: ArmazemChaves = armazemIndexedDB,
): Promise<Autenticador> {
  if ((await armazem.ler(operadorId)) !== null) {
    throw new ErroAssinatura('Já existe chave de assinatura neste navegador.');
  }
  const par = await Autenticador.gerarPar();
  await armazem.gravar(operadorId, par); // grava ANTES de usar: sem persistência, aborta
  return Autenticador.dePar(par);
}
