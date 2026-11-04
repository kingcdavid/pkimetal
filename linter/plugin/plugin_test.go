package plugin

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

func intPtr(i int) *int { return &i }

// writeExecutable creates an executable file named name in dir and returns its path.
func writeExecutable(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildOne(t *testing.T, cfg config.PluginConfig) *linter.Linter {
	t.Helper()
	linters, err := buildLinters([]config.PluginConfig{cfg})
	if err != nil {
		t.Fatalf("buildLinters: %v", err)
	}
	if len(linters) != 1 {
		t.Fatalf("got %d linters, want 1", len(linters))
	}
	return linters[0]
}

func TestBuildLinters_MapsConfig(t *testing.T) {
	dir := t.TempDir()
	command := writeExecutable(t, dir, "subjectcn")

	l := buildOne(t, config.PluginConfig{
		Name:         "subjectcn",
		Command:      command,
		Args:         []string{"--verbose"},
		Dir:          dir,
		NumProcesses: intPtr(3),
		ReadySignal:  true,
		Version:      "1.2.3",
		Url:          "https://example.com/subjectcn",
	})

	if l.Name != "subjectcn" || l.Version != "1.2.3" || l.Url != "https://example.com/subjectcn" {
		t.Errorf("name/version/url: got %q/%q/%q", l.Name, l.Version, l.Url)
	}
	if l.NumInstances != 3 {
		t.Errorf("NumInstances: got %d, want 3", l.NumInstances)
	}
	if l.ReadySignal != linter.PKIMETAL_READY {
		t.Errorf("ReadySignal: got %q, want %q", l.ReadySignal, linter.PKIMETAL_READY)
	}
	if !l.ProfileNameOnWire {
		t.Error("ProfileNameOnWire: got false, want true")
	}
	useHandleRequest, gotDir, gotCmd, gotArgs := l.Interface().StartInstance()
	if useHandleRequest || gotDir != dir || gotCmd != command || !slices.Equal(gotArgs, []string{"--verbose"}) {
		t.Errorf("StartInstance: got (%v, %q, %q, %q)", useHandleRequest, gotDir, gotCmd, gotArgs)
	}
}

func TestBuildLinters_Defaults(t *testing.T) {
	command := writeExecutable(t, t.TempDir(), "plugin")

	l := buildOne(t, config.PluginConfig{Name: "plugin", Command: command})

	if l.NumInstances != 1 {
		t.Errorf("NumInstances: got %d, want 1", l.NumInstances)
	}
	if l.ReadySignal != "" {
		t.Errorf("ReadySignal: got %q, want empty", l.ReadySignal)
	}
	want := slices.Sorted(slices.Values(slices.Concat(linter.CrlProfileIDs, linter.OcspProfileIDs)))
	if !slices.Equal(l.Unsupported, want) {
		t.Errorf("Unsupported: got %v, want CRL+OCSP profiles %v", l.Unsupported, want)
	}
}

func TestBuildLinters_ExplicitZeroDisablesWithoutCheckingCommand(t *testing.T) {
	l := buildOne(t, config.PluginConfig{Name: "plugin", Command: "/does/not/exist", NumProcesses: intPtr(0)})

	if l.NumInstances != 0 {
		t.Errorf("NumInstances: got %d, want 0", l.NumInstances)
	}
}

func TestBuildLinters_Artifacts(t *testing.T) {
	command := writeExecutable(t, t.TempDir(), "plugin")

	for _, tc := range []struct {
		artifacts       []string
		wantSupported   []linter.ProfileId
		wantUnsupported []linter.ProfileId
	}{
		{
			artifacts:       []string{"certificate"},
			wantSupported:   []linter.ProfileId{linter.TBR_LEAF_TLSSERVER_OV, linter.RFC5280_ROOT},
			wantUnsupported: []linter.ProfileId{linter.RFC5280_CRL, linter.TBR_ARL, linter.RFC6960_OCSPRESPONSE},
		},
		{
			artifacts:       []string{"crl"},
			wantSupported:   []linter.ProfileId{linter.RFC5280_CRL, linter.TBR_ARL},
			wantUnsupported: []linter.ProfileId{linter.TBR_LEAF_TLSSERVER_OV, linter.RFC6960_OCSPRESPONSE},
		},
		{
			artifacts:       []string{"ocsp"},
			wantSupported:   []linter.ProfileId{linter.RFC6960_OCSPRESPONSE, linter.TBR_OCSPRESPONSE},
			wantUnsupported: []linter.ProfileId{linter.TBR_LEAF_TLSSERVER_OV, linter.RFC5280_CRL},
		},
		{
			artifacts:     []string{"certificate", "crl", "ocsp"},
			wantSupported: []linter.ProfileId{linter.TBR_LEAF_TLSSERVER_OV, linter.RFC5280_CRL, linter.RFC6960_OCSPRESPONSE},
		},
	} {
		t.Run(strings.Join(tc.artifacts, "+"), func(t *testing.T) {
			l := buildOne(t, config.PluginConfig{Name: "plugin", Command: command, Artifacts: tc.artifacts})

			for _, id := range tc.wantSupported {
				if slices.Contains(l.Unsupported, id) {
					t.Errorf("%s should be supported", linter.AllProfiles[id].Name)
				}
			}
			for _, id := range tc.wantUnsupported {
				if !slices.Contains(l.Unsupported, id) {
					t.Errorf("%s should be unsupported", linter.AllProfiles[id].Name)
				}
			}
			if slices.Contains(l.Unsupported, linter.AUTODETECT) {
				t.Error("autodetect should never be listed as unsupported")
			}
		})
	}
}

func TestBuildLinters_RelativeCommandResolvedAgainstDir(t *testing.T) {
	dir := t.TempDir()
	want := writeExecutable(t, dir, "plugin")

	l := buildOne(t, config.PluginConfig{Name: "plugin", Command: "./plugin", Dir: dir})

	if _, _, gotCmd, _ := l.Interface().StartInstance(); gotCmd != want {
		t.Errorf("command: got %q, want %q", gotCmd, want)
	}
}

func TestBuildLinters_RelativeCommandWithRelativeDir(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	want := writeExecutable(t, filepath.Join(root, "plugins"), "plugin")
	t.Chdir(root)

	l := buildOne(t, config.PluginConfig{Name: "plugin", Command: "plugin", Dir: "plugins"})

	_, gotDir, gotCmd, _ := l.Interface().StartInstance()
	if gotCmd != want {
		t.Errorf("command: got %q, want absolute %q", gotCmd, want)
	}
	if gotDir != "plugins" {
		t.Errorf("dir: got %q, want %q", gotDir, "plugins")
	}
}

func TestBuildLinters_Errors(t *testing.T) {
	dir := t.TempDir()
	executable := writeExecutable(t, dir, "plugin")
	notExecutable := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(notExecutable, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		cfgs    []config.PluginConfig
		wantErr string
	}{
		{"missing name", []config.PluginConfig{{Command: executable}}, "linter.plugins[0]: name is required"},
		{"missing command", []config.PluginConfig{{Name: "p"}}, `plugin "p": command is required`},
		{"relative command without dir", []config.PluginConfig{{Name: "p", Command: "plugin"}}, `plugin "p": command "plugin" is relative, so dir must be set`},
		{"command does not exist", []config.PluginConfig{{Name: "p", Command: filepath.Join(dir, "missing")}}, `plugin "p": command`},
		{"command is a directory", []config.PluginConfig{{Name: "p", Command: dir}}, "is a directory"},
		{"command not executable", []config.PluginConfig{{Name: "p", Command: notExecutable}}, "is not executable"},
		{"unknown artifact", []config.PluginConfig{{Name: "p", Command: executable, Artifacts: []string{"cert"}}}, `unknown artifact "cert"`},
		{"negative numProcesses", []config.PluginConfig{{Name: "p", Command: executable, NumProcesses: intPtr(-1)}}, "numProcesses must not be negative"},
		{"duplicate names", []config.PluginConfig{{Name: "p", Command: executable}, {Name: "p", Command: executable}}, `plugin "p": declared more than once`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildLinters(tc.cfgs)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("got error %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}
