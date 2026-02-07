package api

import "testing"

func TestShellQuoteArgsSimple(t *testing.T) {
	got := ShellQuoteArgs([]string{"echo", "hello"})
	if got != "echo hello" {
		t.Errorf("got %q, want %q", got, "echo hello")
	}
}

func TestShellQuoteArgsWithSpaces(t *testing.T) {
	got := ShellQuoteArgs([]string{"echo", "hello world"})
	if got != "echo 'hello world'" {
		t.Errorf("got %q, want %q", got, "echo 'hello world'")
	}
}

func TestShellQuoteArgsEmpty(t *testing.T) {
	got := ShellQuoteArgs(nil)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestShellQuoteArgsSingleArg(t *testing.T) {
	got := ShellQuoteArgs([]string{"ls"})
	if got != "ls" {
		t.Errorf("got %q, want %q", got, "ls")
	}
}

func TestShellQuoteArgsSpecialChars(t *testing.T) {
	got := ShellQuoteArgs([]string{"echo", "$HOME"})
	if got != "echo '$HOME'" {
		t.Errorf("got %q, want %q", got, "echo '$HOME'")
	}
}

func TestShellQuoteArgsSingleQuoteInArg(t *testing.T) {
	got := ShellQuoteArgs([]string{"echo", "it's"})
	want := `echo 'it'"'"'s'`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestShellQuoteArgsGlob(t *testing.T) {
	got := ShellQuoteArgs([]string{"ls", "*.go"})
	if got != "ls '*.go'" {
		t.Errorf("got %q, want %q", got, "ls '*.go'")
	}
}

func TestShellQuoteArgsMixed(t *testing.T) {
	got := ShellQuoteArgs([]string{"sh", "-c", "echo hello && ls -la"})
	if got != "sh -c 'echo hello && ls -la'" {
		t.Errorf("got %q, want %q", got, "sh -c 'echo hello && ls -la'")
	}
}
