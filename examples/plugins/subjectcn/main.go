// Command subjectcn is an example pkimetal exec plugin; see doc/linters/plugins.md.
//
// It reads requests from STDIN (a profile name line, then a PEM block) and, for
// each one, writes its findings to STDOUT followed by the end-of-results line.
// It warns when the certificate's Subject CN contains "example".
//
// Build it as a static binary so that it runs in pkimetal's Alpine-based image:
//
//	CGO_ENABLED=0 go build -o subjectcn ./examples/plugins/subjectcn
package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	readySignal  = "[Ready]"
	endOfResults = "[EndOfResults]"
)

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "subjectcn:", err)
		os.Exit(1)
	}
}

// run serves requests from in until EOF.  Each response is flushed, otherwise
// pkimetal would wait for buffered output until its backend timeout.
func run(in io.Reader, out io.Writer) error {
	w := bufio.NewWriter(out)
	fmt.Fprintln(w, readySignal)
	if err := w.Flush(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(in)
	var profile string
	var pemBlock strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if profile == "" {
			profile = strings.TrimSpace(line)
			continue
		}
		pemBlock.WriteString(line)
		pemBlock.WriteByte('\n')
		if !strings.HasPrefix(line, "-----END ") {
			continue
		}

		for _, result := range lint(profile, pemBlock.String()) {
			fmt.Fprintln(w, result)
		}
		fmt.Fprintln(w, endOfResults)
		if err := w.Flush(); err != nil {
			return err
		}
		profile = ""
		pemBlock.Reset()
	}
	return scanner.Err()
}

// lint returns the findings for one request, one protocol line each.
func lint(profile, pemBlock string) []string {
	results := []string{"D: profile " + profile}
	block, _ := pem.Decode([]byte(pemBlock))
	if block == nil || block.Type != "CERTIFICATE" {
		return append(results, "F: could not parse certificate: no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		// Each finding must be a single line, or pkimetal would lose sync with the plugin.
		return append(results, "F: could not parse certificate: "+strings.Join(strings.Fields(err.Error()), " "))
	}
	if strings.Contains(strings.ToLower(cert.Subject.CommonName), "example") {
		results = append(results, "W: Subject CN contains 'example'")
	}
	return results
}
