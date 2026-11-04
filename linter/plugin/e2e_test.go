package plugin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

func testCertPEM(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// lintWith sends one request to l and returns its results, up to the end-of-results marker.
func lintWith(t *testing.T, l *linter.Linter, profile linter.ProfileId, input string) []linter.LintingResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	lreq := linter.LintingRequest{
		Ctx:         ctx,
		B64Input:    input,
		ProfileId:   profile,
		QueuedAt:    time.Now(),
		RespChannel: make(chan linter.LintingResult),
	}
	l.ReqChannel <- lreq

	var results []linter.LintingResult
	for {
		select {
		case r := <-lreq.RespChannel:
			if r.LinterName == linter.PKIMETAL_NAME && r.Finding == linter.PKIMETAL_ENDOFRESULTS {
				return results
			}
			results = append(results, r)
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s; got %+v", l.Name, results)
		}
	}
}

func hasResult(results []linter.LintingResult, linterName string, severity linter.SeverityLevel, findingSubstr string) bool {
	for _, r := range results {
		if r.LinterName == linterName && r.Severity == severity && strings.Contains(r.Finding, findingSubstr) {
			return true
		}
	}
	return false
}

func TestExecPlugin_EndToEnd(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not on PATH, so the example plugin cannot be built")
	}
	dir := t.TempDir()
	build := exec.Command(goBinary, "build", "-o", filepath.Join(dir, "subjectcn"), "github.com/pkimetal/pkimetal/examples/plugins/subjectcn")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the example plugin: %v\n%s", err, output)
	}
	// A plugin that dies as soon as it starts, to check that pkimetal survives it.
	if err := os.WriteFile(filepath.Join(dir, "crashes"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	linters, err := buildLinters([]config.PluginConfig{
		{Name: "e2e-subjectcn", Command: "subjectcn", Dir: dir, ReadySignal: true},
		{Name: "e2e-crashes", Command: "crashes", Dir: dir},
	})
	if err != nil {
		t.Fatalf("buildLinters: %v", err)
	}
	for _, l := range linters {
		l.Register()
	}
	subjectcn, crashes := linters[0], linters[1]

	ctx, cancel := context.WithCancel(context.Background())
	linter.StartLinters(ctx)
	t.Cleanup(func() {
		cancel()
		linter.StopLinters(ctx)
		linter.ShutdownWG.Wait()
	})

	results := lintWith(t, subjectcn, linter.TBR_LEAF_TLSSERVER_OV, testCertPEM(t, "www.example.com"))
	if !hasResult(results, "e2e-subjectcn", linter.SEVERITY_DEBUG, "profile tbr_leaf_tlsserver_ov") {
		t.Errorf("plugin did not receive the profile name; got %+v", results)
	}
	if !hasResult(results, "e2e-subjectcn", linter.SEVERITY_WARNING, "Subject CN contains 'example'") {
		t.Errorf("missing the plugin's warning; got %+v", results)
	}

	results = lintWith(t, crashes, linter.TBR_LEAF_TLSSERVER_OV, testCertPEM(t, "www.example.com"))
	if !hasResult(results, linter.PKIMETAL_NAME, linter.SEVERITY_FATAL, "e2e-crashes") {
		t.Errorf("expected a fatal finding for the crashed plugin; got %+v", results)
	}

	// The healthy plugin is unaffected by the crashing one.
	results = lintWith(t, subjectcn, linter.RFC5280_LEAF, testCertPEM(t, "pkimetal.test"))
	if !hasResult(results, "e2e-subjectcn", linter.SEVERITY_DEBUG, "profile rfc5280_leaf") {
		t.Errorf("plugin stopped responding after another plugin crashed; got %+v", results)
	}
}
