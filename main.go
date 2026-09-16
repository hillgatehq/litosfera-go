package main

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"
)

func selectCert(certs []tokenCert, id string) (tokenCert, error) {
	var matches []tokenCert
	for _, c := range certs {
		if id != "" {
			if strings.EqualFold(hex.EncodeToString(c.id), id) {
				matches = append(matches, c)
			}
		} else if strings.Contains(c.cert.Issuer.CommonName, "LB-LITAS-CA") {
			matches = append(matches, c)
		}
	}
	if len(matches) != 1 {
		return tokenCert{}, fmt.Errorf("found %d matching certificates; run -list and select -sign-id / -tls-id", len(matches))
	}
	return matches[0], nil
}
func readPEMCerts(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cs []*x509.Certificate
	for {
		p, rest := pem.Decode(b)
		if p == nil {
			break
		}
		b = rest
		if p.Type == "CERTIFICATE" {
			c, e := x509.ParseCertificate(p.Bytes)
			if e != nil {
				return nil, e
			}
			cs = append(cs, c)
		}
	}
	if len(cs) == 0 {
		return nil, fmt.Errorf("no PEM certificates in %s", path)
	}
	return cs, nil
}
func run() error {
	module := flag.String("module", defaultModulePath(runtime.GOOS, os.Getenv("SystemRoot")), "PKCS#11 module (OS-specific default)")
	slot := flag.Int("slot", -1, "slot ID (automatic with exactly one token)")
	list := flag.Bool("list", false, "list public certificates without logging in")
	signID := flag.String("sign-id", "", "signing certificate CKA_ID, hex")
	tlsID := flag.String("tls-id", "", "TLS certificate CKA_ID, hex; defaults to signing certificate")
	env := flag.String("environment", "", "TEST or PROD; omitted runs both")
	flag.StringVar(env, "env", "", "alias for -environment")
	port := flag.Int("port", 0, "loopback HTTP port; requires -environment or -env")
	rootsPath := flag.String("ca", "", "additional trusted server CAs, PEM")
	chainPath := flag.String("chain", "", "TLS intermediate certificates, PEM (issuer order)")
	crlIssuerPath := flag.String("crl-issuer", "", "trusted CRL issuer certificate, PEM (required with -crl)")
	crlPath := flag.String("crl", "", "current LB-LITAS-CA CRL, DER or PEM, for CRL reference")
	tls12 := flag.Bool("tls12", false, "restrict mTLS to TLS 1.2 if the token does not support RSA-PSS")
	flag.Parse()
	envSet, portSet := false, false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "environment", "env":
			envSet = true
		case "port":
			portSet = true
		}
	})
	listeners, err := listenerConfigs(*env, *port, envSet, portSet)
	if err != nil {
		return err
	}
	t, err := openToken(*module, *slot)
	if err != nil {
		return err
	}
	defer t.Close()
	certs, err := t.certificates()
	if err != nil {
		return err
	}
	if *list {
		for _, c := range certs {
			fmt.Printf("ID=%s label=%q issuer=%q subject=%q expires=%s\n", hex.EncodeToString(c.id), c.label, c.cert.Issuer.String(), c.cert.Subject.String(), c.cert.NotAfter.Format(time.RFC3339))
		}
		return nil
	}
	sc, err := selectCert(certs, *signID)
	if err != nil {
		return err
	}
	tc := sc
	if *tlsID != "" {
		tc, err = selectCert(certs, *tlsID)
		if err != nil {
			return err
		}
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("run interactively to enter the token PIN")
	}
	fmt.Fprint(os.Stderr, "Token PIN: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	err = t.login(pin)
	clear(pin)
	if err != nil {
		return fmt.Errorf("token login failed (not retried): %w", err)
	}
	sk, err := t.signer(sc)
	if err != nil {
		return err
	}
	tk, err := t.signer(tc)
	if err != nil {
		return err
	}
	xs := &xmlSigner{key: sk, cert: sc.cert}
	if *crlPath != "" {
		if *crlIssuerPath == "" {
			return fmt.Errorf("-crl requires -crl-issuer to authenticate the revocation list")
		}
		issuers, e := readPEMCerts(*crlIssuerPath)
		if e != nil {
			return e
		}
		if len(issuers) != 1 {
			return fmt.Errorf("expected exactly one CRL issuer certificate")
		}
		b, e := os.ReadFile(*crlPath)
		if e != nil {
			return e
		}
		if p, _ := pem.Decode(b); p != nil {
			b = p.Bytes
		}
		crl, e := x509.ParseRevocationList(b)
		if e != nil {
			return e
		}
		if e = crl.CheckSignatureFrom(issuers[0]); e != nil {
			return fmt.Errorf("CRL signature: %w", e)
		}
		if e = sc.cert.CheckSignatureFrom(issuers[0]); e != nil {
			return fmt.Errorf("signing certificate issuer: %w", e)
		}
		if time.Now().Before(crl.ThisUpdate) || !time.Now().Before(crl.NextUpdate) {
			return fmt.Errorf("CRL is not current")
		}
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(sc.cert.SerialNumber) == 0 {
				return fmt.Errorf("signing certificate is revoked")
			}
		}
		hash := sha1.Sum(b)
		xs.crlRef = "http://www.lb.lt/pki/crl/?" + base64.StdEncoding.EncodeToString(hash[:])
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{tc.cert.Raw}, PrivateKey: tk, Leaf: tc.cert}
	if *chainPath != "" {
		cs, e := readPEMCerts(*chainPath)
		if e != nil {
			return e
		}
		for _, c := range cs {
			tlsCert.Certificate = append(tlsCert.Certificate, c.Raw)
		}
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	if *rootsPath != "" {
		cs, e := readPEMCerts(*rootsPath)
		if e != nil {
			return e
		}
		for _, c := range cs {
			roots.AddCert(c)
		}
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{tlsCert}}
	if *tls12 {
		cfg.MaxVersion = tls.VersionTLS12
		tlsCert.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.PKCS1WithSHA256, tls.PKCS1WithSHA384, tls.PKCS1WithSHA512}
		cfg.Certificates = []tls.Certificate{tlsCert}
	}
	// Each environment has its own HTTP transport and identity-token cache.
	type boundServer struct {
		server   *http.Server
		listener net.Listener
		config   listenerConfig
	}
	var bound []boundServer
	defer func() {
		for _, b := range bound {
			b.server.Close()
			b.listener.Close()
		}
	}()
	for _, lc := range listeners {
		tr := &http.Transport{TLSClientConfig: cfg.Clone(), TLSHandshakeTimeout: 15 * time.Second}
		defer tr.CloseIdleConnections()
		origin := "https://dstestlitas.lb.lt"
		if lc.environment == "PROD" {
			origin = "https://dslitas.lb.lt"
		}
		ids := &identity{client: &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: origin + "/idsvc", user: "user1", password: "pass1", signer: xs}
		svc := &service{environment: lc.environment, origin: origin, signer: xs, identity: ids}
		server := func() *http.Server {
			return &http.Server{Handler: svc, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
		}
		l, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", lc.port))
		if e != nil {
			return fmt.Errorf("%s listener: %w", lc.environment, e)
		}
		bound = append(bound, boundServer{server(), l, lc})
		if l6, e := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", lc.port)); e == nil {
			bound = append(bound, boundServer{server(), l6, lc})
		}
	}
	// Bind every required port before serving, so a conflict cannot leave a partial startup.
	failures := make(chan error, len(bound))
	for _, b := range bound {
		go func() { failures <- b.server.Serve(b.listener) }()
	}
	for _, lc := range listeners {
		log.Printf("Litosfera Go prototype on loopback port %d; environment=%s", lc.port, lc.environment)
	}
	return <-failures
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

type listenerConfig struct {
	environment string
	port        int
}

func listenerConfigs(env string, port int, envSet, portSet bool) ([]listenerConfig, error) {
	if !envSet {
		if portSet {
			return nil, fmt.Errorf("-port requires -environment or -env")
		}
		return []listenerConfig{{"TEST", 9899}, {"PROD", 9898}}, nil
	}
	if env != "TEST" && env != "PROD" {
		return nil, fmt.Errorf("environment must be TEST or PROD")
	}
	if !portSet {
		port = 9899
		if env == "PROD" {
			port = 9898
		}
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	return []listenerConfig{{env, port}}, nil
}

// Windows redirects System32 to SysWOW64 for a 32-bit process when needed.
func defaultModulePath(goos, systemRoot string) string {
	if goos == "linux" {
		return linuxModulePath(func(path string) bool { info, err := os.Stat(path); return err == nil && info.Mode().IsRegular() })
	}
	if goos == "windows" {
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		return strings.TrimRight(systemRoot, `\/`) + `\System32\eTPKCS11.dll`
	}
	return "/usr/local/lib/libeTPkcs11.dylib"
}

// SafeNet packages use lib64 on some distributions and lib on others.
func linuxModulePath(exists func(string) bool) string {
	for _, path := range []string{"/usr/lib64/libeTPkcs11.so", "/usr/lib/libeTPkcs11.so"} {
		if exists(path) {
			return path
		}
	}
	return "/usr/lib/libeTPkcs11.so"
}
