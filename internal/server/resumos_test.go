package server

import "testing"

func TestParseAtualizacoesWindowsJSON(t *testing.T) {
	r := ParseAtualizacoes("\ufeff" + `{"reinicio_pendente": true, "instaladas": [{"kb":"KB1"}]}`)
	if r.ReinicioPendente == nil || !*r.ReinicioPendente {
		t.Errorf("reinicio = %v", r.ReinicioPendente)
	}
	if r.Pendentes != nil || r.Aviso == "" {
		t.Errorf("windows sem lista de pendentes: quer null+aviso, veio %+v", r)
	}
	r = ParseAtualizacoes(`{"reinicio_pendente": false, "pendentes": [{"kb":"a"},{"kb":"b"}]}`)
	if r.Pendentes == nil || *r.Pendentes != 2 || *r.ReinicioPendente {
		t.Errorf("com lista: %+v", r)
	}
}

func TestParseAtualizacoesLinuxTexto(t *testing.T) {
	out := "reinicio_pendente: sim\n== Pendentes (apt, sem atualizar a lista)\nListing...\n" +
		"openssl/noble-updates 3.0.13 amd64 [upgradable from: 3.0.12]\n" +
		"curl/noble-updates 8.5 amd64 [upgradable from: 8.4]\n" +
		"== Historico recente\n2026-01-01 install foo\n"
	r := ParseAtualizacoes(out)
	if r.Pendentes == nil || *r.Pendentes != 2 || r.ReinicioPendente == nil || !*r.ReinicioPendente {
		t.Errorf("apt: %+v", r)
	}
	r = ParseAtualizacoes("reinicio_pendente: nao\n== Pendentes (apt, sem atualizar a lista)\nListing...\n== Historico recente\n")
	if r.Pendentes == nil || *r.Pendentes != 0 || *r.ReinicioPendente {
		t.Errorf("apt zero: %+v", r)
	}
	r = ParseAtualizacoes("reinicio_pendente: nao\n== Pendentes (dnf)\n\nkernel.x86_64 6.1 updates\nbash.x86_64 5.2 updates\n")
	if r.Pendentes == nil || *r.Pendentes != 2 {
		t.Errorf("dnf: %+v", r)
	}
}

func TestParsersToleramLixo(t *testing.T) {
	for _, in := range []string{"", "   ", "{quebrado", "\x00\xff\xfe", "[1,2]", "null", `{"reinicio_pendente":"talvez","pendentes":{}}`} {
		u := ParseAtualizacoes(in)
		if u.Pendentes != nil || u.Aviso == "" {
			t.Errorf("atualizacoes(%q) = %+v", in, u)
		}
		s := ParseSaude(in)
		if s.Estavel != nil || s.Eventos != nil || s.Aviso == "" {
			t.Errorf("saude(%q) = %+v", in, s)
		}
	}
}

func TestParseSaude(t *testing.T) {
	s := ParseSaude(`{"janela_dias":7,"eventos_instabilidade":3,"estavel":false,"eventos":[]}`)
	if *s.Eventos != 3 || *s.Estavel {
		t.Errorf("win: %+v", s)
	}
	s = ParseSaude("janela_dias: 7\neventos_instabilidade: 0\nestavel: sim\nboots_registrados: 4\n")
	if *s.Eventos != 0 || !*s.Estavel {
		t.Errorf("linux: %+v", s)
	}
	s = ParseSaude("panics: 2\nestavel: nao\n")
	if *s.Eventos != 2 || *s.Estavel {
		t.Errorf("darwin: %+v", s)
	}
	s = ParseSaude("eventos_instabilidade: 5\n")
	if s.Estavel == nil || *s.Estavel {
		t.Errorf("deriva estavel: %+v", s)
	}
}
