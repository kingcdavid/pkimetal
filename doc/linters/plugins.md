# Exec plugins

Exec plugins let you add your own linters to pkimetal without rebuilding it. A plugin is an executable that pkimetal starts and keeps running, sending it one lint request at a time over STDIN and reading its findings from STDOUT. This is the same protocol that pkimetal uses for its built-in certlint, pkilint, and badkeys backends.

## Configuration

Plugins are declared in `config.yaml` (e.g. `/config/config.yaml`) under `linter.plugins`. They cannot be declared with environment variables.

```yaml
linter:
  plugins:
    - name: subjectcn             # Required.  The linter name shown in results; must be unique.
      command: /plugins/subjectcn # Required.  Absolute, or relative to dir.
      args: []                    # Optional command-line arguments.
      dir: /plugins               # Optional working directory.  Required if command is relative.
      numProcesses: 1             # Optional, default 1.  0 disables the plugin.
      readySignal: false          # Optional.  If true, pkimetal waits for "[Ready]" before sending requests.
      artifacts: [certificate]    # Optional, default [certificate].  Any of: certificate, crl, ocsp.
      version: 1.0.0              # Optional.  Shown in the /linters list.
      url: https://example.com    # Optional.  Shown in the /linters list.
```

pkimetal refuses to start if a plugin has no `name` or `command`, if `command` is relative and `dir` is not set, if the command does not exist or is not executable (unless `numProcesses` is 0), if `artifacts` contains an unknown value, or if a plugin's name is already used by another plugin or a built-in linter.

A plugin is only sent requests for the artifact types it lists in `artifacts`.

## Protocol

For each request, pkimetal writes to the plugin's STDIN the profile name on one line, followed by a PEM block:

```
tbr_leaf_tlsserver_ov
-----BEGIN CERTIFICATE-----
MIIF...
-----END CERTIFICATE-----
```

- The profile name is one of those listed by the `/profiles` endpoint.  `autodetect` is always resolved to a specific profile first.
- The PEM block type is `CERTIFICATE`, `X509 CRL`, or `OCSP RESPONSE`, and the request ends with the line that starts with `-----END `.
- Pre-issuance input (e.g. `/linttbscert`) is sent as a normal signed artifact with a dummy signature.

The plugin replies on STDOUT with zero or more result lines, followed by `[EndOfResults]`.  Each result line is either:

- a severity letter, a colon, and a space, followed by the finding: `D: ` (debug), `I: ` (info), `N: ` (notice), `W: ` (warning), `E: ` (error), `B: ` (bug), or `F: ` (fatal).  For example, `W: Subject CN contains 'example'`.
- or one line of JSON in pkilint's format:
  `{"results":[{"node_path":"certificate.tbsCertificate.subject","validator":"MyValidator","finding_descriptions":[{"severity":"ERROR","code":"my_finding_code","message":"..."}]}]}`.
  pkimetal shows `code` as the finding, `node_path` as the field, and ignores `message`.  `severity` must be one of the severity names above (case-insensitive).

A request with no findings gets just `[EndOfResults]`.

## Lifecycle

- pkimetal starts `numProcesses` copies of the plugin, one at a time.  If `readySignal` is true, it waits (without a time limit) for each copy to print `[Ready]` before sending it requests.  Until `[Ready]` arrives, no other backend (built-in or plugin) is started either, so only set `readySignal` for a plugin that prints and flushes `[Ready]`.
- If a plugin's command cannot be executed (for example, a dynamically linked binary that needs glibc, a script whose interpreter is not in the image, or a file that uid 1001 is not allowed to execute), pkimetal exits, logging `Cmd.Start() failed` with the reason.
- Each copy handles one request at a time; all copies share one queue.
- If a copy does not finish its response within `linter.backendTimeout` (default 30s), exits, or writes something that is not a valid result line, that request gets a fatal finding and pkimetal restarts the copy.
- Anything the plugin writes to STDERR is logged by pkimetal.
- On shutdown, pkimetal closes the plugin's STDIN; the plugin should then exit.

## Writing a plugin

- The pkimetal container image is based on Alpine Linux (musl) and runs as uid 1001.  A statically linked binary (e.g. Go with `CGO_ENABLED=0`) is the simplest choice.  `python3` and `ruby` are present in the image, but only with their standard libraries.
- Flush STDOUT after `[Ready]` and after each response.  Otherwise pkimetal waits: indefinitely for `[Ready]`, or until its backend timeout for a response.
- Write nothing to STDOUT except result lines, `[Ready]`, and `[EndOfResults]`, and keep every result on a single line.

[`examples/plugins/subjectcn`](../../examples/plugins/subjectcn/main.go) is a complete example in Go.  It warns when a certificate's Subject CN contains "example".

## Example: running a plugin in the pkimetal container

```bash
CGO_ENABLED=0 go build -o plugins/subjectcn ./examples/plugins/subjectcn
mkdir -p config
cat > config/config.yaml <<'EOF'
linter:
  plugins:
    - name: subjectcn
      command: /plugins/subjectcn
      readySignal: true
      version: 1.0.0
EOF
docker run -p 8080:8080 \
  --mount type=bind,src="$PWD/plugins",dst=/plugins,readonly \
  --mount type=bind,src="$PWD/config",dst=/config,readonly \
  ghcr.io/pkimetal/pkimetal
```
