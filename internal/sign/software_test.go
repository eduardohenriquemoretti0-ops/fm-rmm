package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func parSW(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func itensSW() []SoftwareItem {
	return []SoftwareItem{
		{ID: "firefox", Nome: "Mozilla Firefox", Gerenciador: GerenciadorWinget, PkgID: "Mozilla.Firefox", Publisher: "Mozilla"},
		{ID: "htop", Nome: "htop", Gerenciador: GerenciadorApt, PkgID: "htop", Versao: "3.3.0-4"},
	}
}

func TestCatalogoSoftwareRoundtrip(t *testing.T) {
	raizPub, raiz := parSW(t)
	raw, sig, err := SignSoftwareCatalog(raiz, SoftwareCatalog{Version: 1, IssuedAt: time.Now(), Items: itensSW()})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseSoftwareCatalog(raizPub, raw, sig)
	if err != nil {
		t.Fatalf("parse contra a raiz: %v", err)
	}
	if it, ok := c.Item("htop"); !ok || it.PkgID != "htop" || it.Versao != "3.3.0-4" {
		t.Fatalf("item htop: %+v ok=%v", it, ok)
	}
	if _, ok := c.Item("nao-existe"); ok {
		t.Fatal("item inexistente resolvido")
	}
	// ordem de entrada não muda os bytes (canônico)
	it := itensSW()
	it[0], it[1] = it[1], it[0]
	raw2, _, _ := SignSoftwareCatalog(raiz, SoftwareCatalog{Version: 1, IssuedAt: c.IssuedAt, Items: it})
	if string(raw2) != string(raw) {
		t.Fatal("forma não canônica")
	}
}

func TestCatalogoSoftwareRecusas(t *testing.T) {
	raizPub, raiz := parSW(t)
	outraPub, outra := parSW(t)
	_ = outraPub
	raw, sig, _ := SignSoftwareCatalog(raiz, SoftwareCatalog{Version: 1, IssuedAt: time.Now(), Items: itensSW()})

	// assinatura de outra chave
	rawO, sigO, _ := SignSoftwareCatalog(outra, SoftwareCatalog{Version: 1, IssuedAt: time.Now(), Items: itensSW()})
	if _, err := ParseSoftwareCatalog(raizPub, rawO, sigO); !errors.Is(err, ErrCatalogoAssinatura) {
		t.Fatalf("assinatura de outra chave aceita: %v", err)
	}
	// adulteração do pkg_id
	adul := []byte(strings.Replace(string(raw), "Mozilla.Firefox", "Evil.Malware", 1))
	if _, err := ParseSoftwareCatalog(raizPub, adul, sig); !errors.Is(err, ErrCatalogoAssinatura) {
		t.Fatalf("adulteração aceita: %v", err)
	}
	// a assinatura de uma lista de signers não vale como catálogo (e vice-versa)
	rawL, sigL, _ := SignSignerList(raiz, SignerList{Version: 1, IssuedAt: time.Now()})
	if _, err := ParseSoftwareCatalog(raizPub, rawL, sigL); !errors.Is(err, ErrCatalogoMalformado) {
		t.Fatalf("lista de signers aceita como catálogo: %v", err)
	}
	// itens inválidos (injeção) nem chegam a ser assinados
	for _, pkg := range []string{"x; rm -rf /", "-oFoo", "a b", "$(id)", "a|b", ""} {
		_, _, err := SignSoftwareCatalog(raiz, SoftwareCatalog{Version: 1, IssuedAt: time.Now(),
			Items: []SoftwareItem{{ID: "x", Nome: "X", Gerenciador: GerenciadorWinget, PkgID: pkg}}})
		if !errors.Is(err, ErrCatalogoMalformado) {
			t.Errorf("pkg_id %q aceito: %v", pkg, err)
		}
	}
	for _, it := range []SoftwareItem{
		{ID: "Maiusc", Nome: "X", Gerenciador: GerenciadorApt, PkgID: "htop"},
		{ID: "-x", Nome: "X", Gerenciador: GerenciadorApt, PkgID: "htop"},
		{ID: "x", Nome: "X", Gerenciador: "choco", PkgID: "htop"},
		{ID: "x", Nome: "X", Gerenciador: GerenciadorApt, PkgID: "htop", Versao: "1;2"},
		{ID: "x", Nome: "X", Gerenciador: GerenciadorApt, PkgID: "htop", SHA256: "abc"},
	} {
		if err := it.Validar(); err == nil {
			t.Errorf("item inválido aceito: %+v", it)
		}
	}
	// id duplicado
	d := itensSW()
	d[1].ID = "firefox"
	if _, _, err := SignSoftwareCatalog(raiz, SoftwareCatalog{Version: 1, IssuedAt: time.Now(), Items: d}); err == nil {
		t.Fatal("id duplicado aceito")
	}
}
