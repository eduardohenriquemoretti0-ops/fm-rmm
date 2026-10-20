//go:build !windows

package agent

// runInUserSession só existe no Windows; nos outros SOs fica nil e o winget
// (que também só é montado em Windows por MontarSoftware) nunca é chamado.
var runInUserSession cmdRunner
