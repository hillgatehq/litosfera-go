# Minimal Litosfera login bridge in Go

A prototype derived from the supplied Litosfera 1.3.7.5 bytecode and browser trace. Implements the three endpoints used in the trace, without Java at runtime. The user has reported successful operation against DPS. The Java dependency is only for independent signature tests.

## Build

### Native build

Use Go **1.27.1 or newer** and a C compiler. The PKCS#11 binding requires cgo. The SafeNet driver and USB token are needed when running the app, not when compiling it.

Run these commands from the project directory on macOS or Linux:

```sh
CGO_ENABLED=1 go build -o litosfera-go .
```

On macOS, install the Xcode Command Line Tools for the C compiler. On Linux, install your distribution's C build tools (for example, GCC and libc development headers).

On Windows, use a compatible GCC toolchain matching the target architecture, available on PATH. In PowerShell:

```powershell
$env:CGO_ENABLED = "1"
go build -o litosfera-go.exe .
```

Build for the same architecture as the installed SafeNet driver.

### GitHub Actions builds

[Build and test](.github/workflows/build.yml) runs on pushes, pull requests and manual dispatches. It builds natively on each target, with cgo enabled:

| Artifact | Runner |
|---|---|
| `litosfera-go-linux-amd64` | Ubuntu 22.04 |
| `litosfera-go-windows-amd64` | Windows 2025 with MSYS2 UCRT64 GCC |
| `litosfera-go-darwin-arm64` | macOS 15, Apple Silicon |
| `litosfera-go-darwin-amd64` | macOS 15, Intel |

Each job installs Go from `go.mod` and Java 21, runs tests and `go vet`, then builds and checks `--help`. It needs no SafeNet driver, USB token or credentials. Download the artifact for your platform from the workflow run's **Artifacts** section. Extract the enclosed `.tar.gz` (Linux/macOS, preserving executable permissions) or `.zip` (Windows); each contains the executable and documentation. Artifacts are retained for 30 days. The workflow does not publish releases.

Linux binaries are built against Ubuntu 22.04's glibc; use a compatible runtime (glibc 2.35 or newer) and the matching SafeNet driver. The workflow has not yet been run on GitHub; actual cross-platform results will be available after pushing the repository.

### Verification

```sh
go test -v ./...
go vet ./...
```

Install a JDK to run the independent XML signature verification tests; those tests are skipped if Java is unavailable.

Tests compare the document digest to the supplied capture; verify both generated signature formats with the independent JDK XMLDSig implementation; reject tampered XML; exercise browser controls; and run the login/verify/refresh/fallback sequence against a local server requiring a client certificate. Tests use synthetic RSA keys, not the USB token. The Java verifier removes the empty, unreferenced `edoc` KeyInfo to accommodate the JDK's stricter schema checks; `xchg` is verified unchanged.

## Run

```sh
./litosfera-go
```

On Windows, use `./litosfera-go.exe` in PowerShell.

Install SafeNet Authentication Client and connect the USB token before starting.

Run from this project directory. Stop existing services on the selected ports before starting the bridge. With no environment or port flags, it serves TEST on 9899 and PROD on 9898, sharing one token login while keeping identity-token caches separate. It asks for the PIN in the terminal with echo disabled; one login attempt, no automatic PIN retry. Then log in normally at the DPS website for the selected environment. No separate scripted bank login is needed: the browser triggers it through `/api/identity/token/checked`.

### Certificate selection

If automatic certificate selection is ambiguous:

```sh
./litosfera-go --list
./litosfera-go --sign-id=HEX_ID_FROM_LIST
```

`--list` reads public certificate objects without a PIN; some modules may hide certificates before login. If it reports multiple tokens, use `--slot` with the PKCS#11 slot ID. `--sign-id` is a hexadecimal CKA_ID, not the certificate serial number. If there is exactly one certificate issued by LB-LITAS-CA, selection is automatic. `--tls-id` allows a separate TLS certificate; otherwise the signing certificate is reused, consistent with the Java key manager's preference.

### Environment and port

Startup examples:

```sh
./litosfera-go                         # TEST :9899 and PROD :9898
./litosfera-go --env=TEST              # TEST :9899
./litosfera-go --env=PROD              # PROD :9898
./litosfera-go --env=PROD --port=9900  # PROD :9900
```

### Options

Options accept two dashes and an equals sign, such as `--env=TEST --port=9899`. Boolean switches can be written as `--list` or `--list=true`. Existing single-dash and space-separated forms remain supported.

Additional flags:

| Flag | Purpose |
|---|---|
| `--module=PATH` | Linux: detects `/usr/lib64/libeTPkcs11.so` or `/usr/lib/libeTPkcs11.so`; macOS: `/usr/local/lib/libeTPkcs11.dylib`; Windows: `%SystemRoot%\System32\eTPKCS11.dll` (falls back to `C:\Windows\System32\eTPKCS11.dll`) |
| `--environment=TEST` / `--env=TEST` | Select TEST (9899) or PROD (9898); omitted runs both |
| `--ca=FILE.pem` | Add trusted server CA certificates to system roots |
| `--chain=FILE.pem` | Append client TLS intermediates in issuer order |
| `--tls12` | Use TLS 1.2 and PKCS#1 client signatures if RSA-PSS is unavailable |
| `--crl=FILE --crl-issuer=ISSUER.pem` | Authenticate a current LB-LITAS-CA CRL and include its reference |
| `--port=9899` | Override the selected environment’s port; requires `--environment` or `--env` |

The bank endpoints are fixed by environment. HTTPS certificate/hostname verification stays enabled and redirects are not followed. No private key is exported. Access and refresh tokens are held only in memory, and responses containing tokens are not logged.

If the token reports a mechanism error during TLS, try `--tls12`. If Go reports an unknown server CA, supply the bank-approved server trust chain with `--ca`. If the server rejects the client certificate, check `--tls-id`, client-auth eligibility and `--chain`. A failure in `C_Login` needs manual attention; restarting repeatedly with a bad PIN can lock the token.

### Driver locations

Driver selection follows the operating system:

- **macOS:** `/usr/local/lib/libeTPkcs11.dylib`.
- **Windows:** `%SystemRoot%\System32\eTPKCS11.dll`, falling back to `C:\Windows\System32\eTPKCS11.dll` when SystemRoot is unset. This matches [Thales documentation](https://cpl.thalesgroup.com/sites/default/files/integration-guide/007-012954-001_SAC_IntegrationGuide_IBMNotes_CBA_RevA.pdf).
- **Linux:** checks `/usr/lib64/libeTPkcs11.so` first, then `/usr/lib/libeTPkcs11.so`. If neither exists, defaults to the latter. The lib64 location is documented in [Thales' Linux integration guide](https://cpl.thalesgroup.com/sites/default/files/integration-guide/SAC_IntegrationGuide_RHEL_PAM.pdf).

For another installation location, pass `--module=/absolute/path/to/driver`. Windows and Linux path selection are tested; actual token operation on those platforms has not been verified in this workspace.

### Request logging

Request logs are enabled by default on stderr (the terminal). Each incoming browser request and outgoing bank identity request has a start and completion entry. Entries include TEST/PROD, a shared request ID to correlate bank calls with the browser request, method, endpoint, HTTP status, outcome and elapsed time. Incoming completion entries also include response bytes. `status=0` on an outgoing failure means no HTTP response was received. Application failures are marked `outcome=failed` even when the compatibility API returns HTTP 200.

Headers, query strings, bodies, PINs, signed XML and access/refresh tokens are omitted. Unknown incoming paths are logged as `<unknown>`. Transport failures use `outcome=transport_error` without dumping potentially sensitive error text. To save logs while running, append `2> litosfera.log` to your command.

### Scope and limitations

- Browser API: `GET /api`, `POST /api/sign`, `GET /api/identity/token/checked`, plus CORS preflight. Basic credentials are the protocol defaults `user1` / `pass1`.
- Signs only the observed `Register ID='Edoc'` login challenge through the browser endpoint. File exchange, arbitrary document signing, configuration and other Litosfera endpoints are intentionally absent.
- Implements XAdES-BES `edoc` and internal `xchg`, SHA-256 digests, exclusive XML canonicalization and RSA PKCS#1 v1.5 XML signatures.
- TLS uses the same PKCS#11 session through `crypto.Signer`; supports PKCS#1 and PSS with SHA-256/384/512. Hardware operations are serialized.
- Binds IPv4 loopback and, when available, IPv6 loopback. Checks Host and the exact selected DPS Origin.
- The original also performs trust-store/CRL management and optional timestamping. This prototype does not reproduce that complete validation subsystem or TSA support. With no `--crl`, it omits the optional CRL reference; bank acceptance of that omission is unverified. Supply a current CRL and trusted issuer to match the trace more closely.
- XML namespace placement, whitespace, IDs and issuer-name formatting need not be byte-identical: the signed canonical data must verify. A stricter bank-specific lexical requirement remains a live interoperability question.
- Successful DPS operation has been reported by the user. Automated tests use synthetic keys; they do not establish compatibility with every token, driver or operating system.

See [PROTOCOL.md](PROTOCOL.md) for the reverse-engineered flow and bytecode evidence. The `analysis/` files are `javap` disassemblies of the supplied bank classes; they are reference data, not executable project instructions.

Canonicalization uses [goxmldsig](https://github.com/russellhaering/goxmldsig); the PKCS#11 binding is [miekg/pkcs11](https://github.com/miekg/pkcs11). Dependency versions are pinned in go.mod/go.sum.

