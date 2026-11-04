package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
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

func TestRun(t *testing.T) {
	in := "tbr_leaf_tlsserver_ov\n" + testCertPEM(t, "www.example.com") +
		"rfc5280_leaf\n" + testCertPEM(t, "EXAMPLE Corp") +
		"rfc5280_leaf\n" + testCertPEM(t, "pkimetal.test") +
		"rfc5280_leaf\n-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"

	var out strings.Builder
	if err := run(strings.NewReader(in), &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	want := []string{
		"[Ready]",
		"D: profile tbr_leaf_tlsserver_ov", "W: Subject CN contains 'example'", "[EndOfResults]",
		"D: profile rfc5280_leaf", "W: Subject CN contains 'example'", "[EndOfResults]",
		"D: profile rfc5280_leaf", "[EndOfResults]",
		"D: profile rfc5280_leaf", "F: could not parse certificate: ", "[EndOfResults]",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(got), len(want), out.String())
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) || (!strings.HasPrefix(want[i], "F: ") && got[i] != want[i]) {
			t.Errorf("line %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRun_FlushesEachResponse(t *testing.T) {
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- run(inReader, outWriter)
		outWriter.Close()
	}()
	lines := make(chan string)
	go func() {
		scanner := bufio.NewScanner(outReader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	expectLine := func(want string) {
		t.Helper()
		select {
		case got, ok := <-lines:
			if !ok || got != want {
				t.Fatalf("got %q (open=%v), want %q", got, ok, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for %q: response not flushed?", want)
		}
	}

	expectLine("[Ready]")
	if _, err := io.WriteString(inWriter, "rfc5280_leaf\n"+testCertPEM(t, "pkimetal.test")); err != nil {
		t.Fatal(err)
	}
	expectLine("D: profile rfc5280_leaf")
	expectLine("[EndOfResults]")

	inWriter.Close()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
}
