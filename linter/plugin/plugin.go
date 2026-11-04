// Package plugin registers exec plugins: operator-supplied executables, declared
// under linter.plugins in config.yaml, that pkimetal runs as long-lived linter
// backends using the same STDIN/STDOUT protocol as its built-in external
// linters.  See doc/linters/plugins.md.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

// Values accepted in a plugin's "artifacts" list.
const (
	ArtifactCertificate = "certificate"
	ArtifactCRL         = "crl"
	ArtifactOCSP        = "ocsp"
)

type execPlugin struct {
	directory string
	command   string
	args      []string
}

func init() {
	linters, err := buildLinters(config.Config.Linter.Plugins)
	if err != nil {
		panic("plugin: " + err.Error())
	}
	for _, l := range linters {
		l.Register() // Register panics if a plugin's name clashes with any other linter's.
	}
}

// buildLinters validates the plugin declarations and converts each one into a
// linter.Linter, ready to be registered.
func buildLinters(cfgs []config.PluginConfig) ([]*linter.Linter, error) {
	var linters []*linter.Linter
	seen := make(map[string]bool)
	for i, cfg := range cfgs {
		if cfg.Name == "" {
			return nil, fmt.Errorf("linter.plugins[%d]: name is required", i)
		}
		if seen[cfg.Name] {
			return nil, fmt.Errorf("plugin %q: declared more than once", cfg.Name)
		}
		seen[cfg.Name] = true

		l, err := buildLinter(cfg)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", cfg.Name, err)
		}
		linters = append(linters, l)
	}
	return linters, nil
}

func buildLinter(cfg config.PluginConfig) (*linter.Linter, error) {
	numInstances := 1
	if cfg.NumProcesses != nil {
		numInstances = *cfg.NumProcesses
	}
	if numInstances < 0 {
		return nil, fmt.Errorf("numProcesses must not be negative, got %d", numInstances)
	}

	command, err := resolveCommand(cfg.Command, cfg.Dir)
	if err != nil {
		return nil, err
	}
	// A disabled plugin's executable need not be present.
	if numInstances > 0 {
		if err = checkExecutable(command); err != nil {
			return nil, err
		}
	}

	unsupported, err := unsupportedProfiles(cfg.Artifacts)
	if err != nil {
		return nil, err
	}

	var readySignal string
	if cfg.ReadySignal {
		readySignal = linter.PKIMETAL_READY
	}

	backend := &execPlugin{directory: cfg.Dir, command: command, args: cfg.Args}
	return &linter.Linter{
		Name:              cfg.Name,
		Version:           cfg.Version,
		Url:               cfg.Url,
		Unsupported:       unsupported,
		NumInstances:      numInstances,
		ReadySignal:       readySignal,
		ProfileNameOnWire: true,
		Interface:         func() linter.LinterInterface { return backend },
	}, nil
}

// resolveCommand returns the plugin's executable as an absolute path.  A relative
// command is resolved against dir here, because Go would otherwise evaluate it
// relative to the backend's working directory (also dir), applying dir twice.
func resolveCommand(command, dir string) (string, error) {
	if command == "" {
		return "", errors.New("command is required")
	}
	if filepath.IsAbs(command) {
		return command, nil
	}
	if dir == "" {
		return "", fmt.Errorf("command %q is relative, so dir must be set", command)
	}
	return filepath.Abs(filepath.Join(dir, command))
}

func checkExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("command: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("command %s is a directory", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("command %s is not executable", path)
	}
	return nil
}

// unsupportedProfiles returns the profiles whose artifact type is not in
// artifacts (default: certificates only), so that the plugin is only sent the
// artifact types it declares.
func unsupportedProfiles(artifacts []string) ([]linter.ProfileId, error) {
	if len(artifacts) == 0 {
		artifacts = []string{ArtifactCertificate}
	}
	for _, artifact := range artifacts {
		switch artifact {
		case ArtifactCertificate, ArtifactCRL, ArtifactOCSP:
		default:
			return nil, fmt.Errorf("unknown artifact %q (want %s, %s or %s)", artifact, ArtifactCertificate, ArtifactCRL, ArtifactOCSP)
		}
	}

	var unsupported []linter.ProfileId
	for id := range linter.AllProfiles {
		if id != linter.AUTODETECT && !slices.Contains(artifacts, artifactOf(id)) {
			unsupported = append(unsupported, id)
		}
	}
	slices.Sort(unsupported)
	return unsupported, nil
}

func artifactOf(id linter.ProfileId) string {
	switch {
	case slices.Contains(linter.CrlProfileIDs, id):
		return ArtifactCRL
	case slices.Contains(linter.OcspProfileIDs, id):
		return ArtifactOCSP
	default:
		return ArtifactCertificate
	}
}

func (p *execPlugin) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return false, p.directory, p.command, p.args // Plugins are always external backends.
}

func (p *execPlugin) StopInstance(lin *linter.LinterInstance) {
}

func (p *execPlugin) HandleRequest(ctx context.Context, lin *linter.LinterInstance, lreq *linter.LintingRequest) []linter.LintingResult {
	return nil // Unused: requests are sent over the backend's STDIN by the linter server loop.
}

func (p *execPlugin) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
