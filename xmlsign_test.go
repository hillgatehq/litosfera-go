package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func testSigner(t *testing.T) *xmlSigner {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "Test participant"}, Issuer: pkix.Name{CommonName: "Test participant"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true, DNSNames: []string{"localhost"}}
	b, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(b)
	if e != nil {
		t.Fatal(e)
	}
	return &xmlSigner{key: key, cert: cert}
}
func TestCapturedDigest(t *testing.T) {
	d := etree.NewDocument()
	if err := d.ReadFromString(`<EDoc><Register ID="Edoc">2026-09-16T19:59:47</Register></EDoc>`); err != nil {
		t.Fatal(err)
	}
	got, e := digest(d.Root())
	if e != nil {
		t.Fatal(e)
	}
	if got != "hl+t70PGvP7Pc2DwXx9odqMqal99WR6CKaFE35CaNjc=" {
		t.Fatal(got)
	}
}
func TestJavaVerification(t *testing.T) {
	if _, e := exec.LookPath("java"); e != nil {
		t.Skip("Java is needed for independent verification")
	}
	s := testSigner(t)
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.der")
	if e := os.WriteFile(cert, s.cert.Raw, 0600); e != nil {
		t.Fatal(e)
	}
	for _, typ := range []string{"edoc", "xchg"} {
		t.Run(typ, func(t *testing.T) {
			input := xchgXML
			if typ == "edoc" {
				input = `<Register ID='Edoc'>2026-09-16T19:59:47</Register>`
			}
			out, e := s.sign(input, typ, time.Now())
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(dir, typ+".xml")
			if e = os.WriteFile(path, []byte(out), 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command("java", "testdata/Verify.java", path, cert)
			if b, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("Java verifier: %v\n%s", e, b)
			}
			d := etree.NewDocument()
			d.ReadFromString(out)
			d.Root().CreateAttr("tampered", "true")
			b, _ := d.WriteToBytes()
			os.WriteFile(path, b, 0600)
			if e = exec.Command("java", "testdata/Verify.java", path, cert).Run(); e == nil {
				t.Fatal("tampered document accepted")
			}
		})
	}
}
