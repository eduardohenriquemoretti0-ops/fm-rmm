package sign

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func scriptsTeste() []ScriptEntry {
	c1, c2 := "echo limpando temp\n", "Get-Service | Out-Null\n"
	return []ScriptEntry{
		{ID: "limpar-temp", Nome: "Limpar /tmp", Versao: "1.0.0", Interprete: InterpreteBash, Corpo: c1, SHA256: HashCorpoScript(c1)},
		{ID: "listar-servicos", Nome: "Listar serviços", Versao: "2.1", Interprete: InterpretePowerShell, Corpo: c2, SHA256: HashCorpoScript(c2)},
	}
}

func TestBibliotecaScriptsRoundtripEAssinatura(t *testing.T) {
	raizPub, raiz := parSW(t)
	raw, sig, err := SignScriptLibrary(raiz, ScriptLibrary{Version: 1, IssuedAt: time.Now(), Scripts: scriptsTeste()})
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseScriptLibrary(raizPub, raw, sig)
	if err != nil {
		t.Fatalf("parse contra a raiz: %v", err)
	}
	if e, ok := l.Script("limpar-temp", "1.0.0"); !ok || e.Interprete != InterpreteBash {
		t.Fatalf("entrada: %+v ok=%v", e, ok)
	}
	if _, ok := l.Script("limpar-temp", "9.9"); ok {
		t.Fatal("versão inexistente resolveu")
	}
	outraPub, _ := parSW(t)
	if _, err := ParseScriptLibrary(outraPub, raw, sig); !errors.Is(err, ErrBibliotecaAssinatura) {
		t.Fatalf("outra raiz: %v", err)
	}
	adulterado := []byte(strings.Replace(string(raw), "limpando", "apagando", 1))
	if _, err := ParseScriptLibrary(raizPub, adulterado, sig); !errors.Is(err, ErrBibliotecaAssinatura) {
		t.Fatalf("corpo adulterado após assinar: %v", err)
	}
	t.Logf("roundtrip ok: %d bytes canônicos, %d scripts", len(raw), len(l.Scripts))
}

func TestBibliotecaScriptsKindImpedeCrossUse(t *testing.T) {
	raizPub, raiz := parSW(t)
	rawSW, sigSW, _ := SignSoftwareCatalog(raiz, SoftwareCatalog{Version: 1, IssuedAt: time.Now(), Items: itensSW()})
	if _, err := ParseScriptLibrary(raizPub, rawSW, sigSW); err == nil {
		t.Fatal("catálogo de software aceito como biblioteca de scripts")
	}
	rawS, sigS, _ := SignScriptLibrary(raiz, ScriptLibrary{Version: 1, IssuedAt: time.Now(), Scripts: scriptsTeste()})
	if _, err := ParseSoftwareCatalog(raizPub, rawS, sigS); err == nil {
		t.Fatal("biblioteca de scripts aceita como catálogo de software")
	}
	if _, err := ParseSignerList(raizPub, rawS, sigS); err == nil {
		t.Fatal("biblioteca de scripts aceita como lista de signers")
	}
}

func TestBibliotecaScriptsValidacao(t *testing.T) {
	_, raiz := parSW(t)
	ok := scriptsTeste()[0]
	muta := func(f func(*ScriptEntry)) ScriptEntry { e := ok; f(&e); return e }
	maus := map[string]ScriptEntry{
		"id com ;":            muta(func(e *ScriptEntry) { e.ID = "a;b" }),
		"id maiúsculo":        muta(func(e *ScriptEntry) { e.ID = "Limpar" }),
		"id com -inicial":     muta(func(e *ScriptEntry) { e.ID = "-x" }),
		"versão com espaço":   muta(func(e *ScriptEntry) { e.Versao = "1 0" }),
		"versão com $(":       muta(func(e *ScriptEntry) { e.Versao = "1$(x)" }),
		"versão não numérica": muta(func(e *ScriptEntry) { e.Versao = "v1" }),
		"interpretador":       muta(func(e *ScriptEntry) { e.Interprete = "python" }),
		"sha256 diverge":      muta(func(e *ScriptEntry) { e.Corpo = "rm -rf /\n" }),
		"sha256 vazio":        muta(func(e *ScriptEntry) { e.SHA256 = "" }),
		"corpo vazio":         muta(func(e *ScriptEntry) { e.Corpo = ""; e.SHA256 = HashCorpoScript("") }),
		"corpo com NUL":       muta(func(e *ScriptEntry) { e.Corpo = "a\x00b"; e.SHA256 = HashCorpoScript(e.Corpo) }),
	}
	for nome, e := range maus {
		if _, _, err := SignScriptLibrary(raiz, ScriptLibrary{Version: 1, IssuedAt: time.Now(), Scripts: []ScriptEntry{e}}); err == nil {
			t.Errorf("%s: aceito", nome)
		}
	}
	dup := []ScriptEntry{ok, ok}
	if _, _, err := SignScriptLibrary(raiz, ScriptLibrary{Version: 1, IssuedAt: time.Now(), Scripts: dup}); err == nil {
		t.Error("id+versão duplicados aceitos")
	}
	// mesma id, versões distintas: permitido
	v2 := ok
	v2.Versao = "1.1.0"
	if _, _, err := SignScriptLibrary(raiz, ScriptLibrary{Version: 1, IssuedAt: time.Now(), Scripts: []ScriptEntry{ok, v2}}); err != nil {
		t.Errorf("duas versões do mesmo script: %v", err)
	}
	if _, _, err := SignScriptLibrary(raiz, ScriptLibrary{Version: 0, IssuedAt: time.Now()}); err == nil {
		t.Error("versão 0 aceita")
	}
}
