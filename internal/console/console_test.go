package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d, quer 200", rec.Code)
	}
	want := map[string]string{
		"X-Content-Type-Options":     "nosniff",
		"X-Frame-Options":            "DENY",
		"Referrer-Policy":            "no-referrer",
		"Cross-Origin-Opener-Policy": "same-origin",
		"Cache-Control":              "no-store",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("header %s = %q, quer %q", k, got, v)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, must := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, must) {
			t.Errorf("CSP sem %q: %q", must, csp)
		}
	}
	for _, forbid := range []string{"unsafe-inline", "unsafe-eval"} {
		if strings.Contains(csp, forbid) {
			t.Errorf("CSP não pode ter %q: %q", forbid, csp)
		}
	}
	if hsts := rec.Header().Get("Strict-Transport-Security"); !strings.Contains(hsts, "includeSubDomains") {
		t.Errorf("HSTS fraco: %q", hsts)
	}
}

func TestSessionCookieTravas(t *testing.T) {
	c := SessionCookie("fmrmm_sess", "abc", 15*time.Minute)
	if !c.HttpOnly {
		t.Error("cookie sem HttpOnly")
	}
	if !c.Secure {
		t.Error("cookie sem Secure")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Error("cookie sem SameSite=Strict")
	}
	if c.MaxAge != 900 {
		t.Errorf("MaxAge = %d, quer 900", c.MaxAge)
	}
}
