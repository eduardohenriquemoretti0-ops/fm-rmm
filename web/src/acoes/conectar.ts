/**
 * PONTO DE EXTENSÃO do botão "Conectar" (sessão remota / ações).
 *
 * Hoje é um stub: não chama API nenhuma e não assina nada. Quando o T5 existir,
 * este módulo deve:
 *   1. checar RBAC/step-up (o console só mostra controle com permissão);
 *   2. montar o payload canônico e pedir a assinatura ao autenticador WebCrypto (T7);
 *   3. enviar a POST /api/acoes com a assinatura e o CSRF (api/cliente.ts).
 * Até lá, nada aqui pode executar ação no agente.
 */
import type { Agente } from '../api/tipos';

export type ResultadoConectar = {
  readonly disponivel: false;
  readonly motivo: string;
};

export function conectarAgente(_agente: Agente): ResultadoConectar {
  return {
    disponivel: false,
    motivo:
      'Conectar ainda não está disponível: aguarda POST /api/acoes (T5) e o autenticador de assinatura (T7).',
  };
}
