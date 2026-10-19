// Package console é o servidor do console web do FM-RMM (read-only + fila de
// escrita assinada no cliente). Este arquivo traz só o endurecimento HTTP
// (headers, CSP, cookie de sessão); a autenticação do operador (WebAuthn + mTLS),
// os endpoints e a re-verificação de assinatura entram nos próximos incrementos.
//
// Spec de segurança: docs/console-seguranca.md (alvo do pentest interno).
package console

import (
	"net/http"
	"time"
)

// CSP estrito: nada por padrão; só o próprio SPA (self). Sem inline/eval — o
// bootstrap do SPA usa nonce/hash, nunca `unsafe-inline`.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; manifest-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// SecurityHeaders aplica os cabeçalhos de endurecimento em toda resposta.
// É a primeira camada contra XSS, clickjacking, sniffing e vazamento de referer.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		// não cacheia resposta autenticada por engano
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// SessionCookie monta o cookie do token de sessão com as travas obrigatórias:
// HttpOnly (JS não lê → XSS não rouba), Secure (só HTTPS), SameSite=Strict
// (1ª camada anti-CSRF). O token NUNCA vai para localStorage.
func SessionCookie(name, value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(ttl / time.Second),
	}
}

// Handler devolve o mux do console já embrulhado no endurecimento. Por enquanto
// só expõe /healthz; os endpoints autenticados entram nos próximos incrementos.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	return SecurityHeaders(mux)
}
