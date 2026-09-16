package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	p11 "github.com/miekg/pkcs11"
)

type token struct {
	p        *p11.Ctx
	session  p11.SessionHandle
	mu       sync.Mutex
	loggedIn bool
}
type tokenCert struct {
	cert  *x509.Certificate
	id    []byte
	label string
}
type tokenSigner struct {
	t   *token
	key p11.ObjectHandle
	pub *rsa.PublicKey
}

func openToken(path string, slotID int) (*token, error) {
	p := p11.New(path)
	if p == nil {
		return nil, fmt.Errorf("load PKCS#11 module %s", path)
	}
	if err := p.Initialize(); err != nil {
		p.Destroy()
		return nil, err
	}
	fail := func(err error) (*token, error) { p.Finalize(); p.Destroy(); return nil, err }
	slots, err := p.GetSlotList(true)
	if err != nil {
		return fail(err)
	}
	if slotID < 0 {
		if len(slots) != 1 {
			return fail(fmt.Errorf("found %d tokens; select one with -slot", len(slots)))
		}
		slotID = int(slots[0])
	}
	s, err := p.OpenSession(uint(slotID), p11.CKF_SERIAL_SESSION)
	if err != nil {
		return fail(err)
	}
	return &token{p: p, session: s}, nil
}
func (t *token) Close() {
	if t.loggedIn {
		t.p.Logout(t.session)
	}
	t.p.CloseSession(t.session)
	t.p.Finalize()
	t.p.Destroy()
}
func (t *token) login(pin []byte) error {
	err := t.p.Login(t.session, p11.CKU_USER, string(pin))
	if errors.Is(err, p11.Error(p11.CKR_USER_ALREADY_LOGGED_IN)) {
		return nil
	}
	if err == nil {
		t.loggedIn = true
	}
	return err
}
func (t *token) find(attrs []*p11.Attribute) ([]p11.ObjectHandle, error) {
	if err := t.p.FindObjectsInit(t.session, attrs); err != nil {
		return nil, err
	}
	var result []p11.ObjectHandle
	for {
		objects, _, err := t.p.FindObjects(t.session, 100)
		if err != nil {
			t.p.FindObjectsFinal(t.session)
			return nil, err
		}
		result = append(result, objects...)
		if len(objects) == 0 {
			break
		}
	}
	return result, t.p.FindObjectsFinal(t.session)
}
func (t *token) certificates() ([]tokenCert, error) {
	objs, err := t.find([]*p11.Attribute{p11.NewAttribute(p11.CKA_CLASS, p11.CKO_CERTIFICATE)})
	if err != nil {
		return nil, err
	}
	var certs []tokenCert
	for _, o := range objs {
		a, e := t.p.GetAttributeValue(t.session, o, []*p11.Attribute{p11.NewAttribute(p11.CKA_VALUE, nil), p11.NewAttribute(p11.CKA_ID, nil), p11.NewAttribute(p11.CKA_LABEL, nil)})
		if e != nil {
			return nil, e
		}
		c, e := x509.ParseCertificate(a[0].Value)
		if e != nil {
			continue
		}
		certs = append(certs, tokenCert{c, a[1].Value, string(a[2].Value)})
	}
	return certs, nil
}
func (t *token) signer(c tokenCert) (crypto.Signer, error) {
	pub, ok := c.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate is not RSA")
	}
	if len(c.id) == 0 {
		return nil, fmt.Errorf("certificate has empty CKA_ID")
	}
	keys, err := t.find([]*p11.Attribute{p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY), p11.NewAttribute(p11.CKA_ID, c.id)})
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("expected one key for CKA_ID %s, found %d", hex.EncodeToString(c.id), len(keys))
	}
	return &tokenSigner{t, keys[0], pub}, nil
}
func (s *tokenSigner) Public() crypto.PublicKey { return s.pub }
func (s *tokenSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.t.mu.Lock()
	defer s.t.mu.Unlock()
	h := opts.HashFunc()
	if len(digest) != h.Size() {
		return nil, fmt.Errorf("incorrect digest length")
	}
	var hash, mgf uint
	var prefix string
	switch h {
	case crypto.SHA256:
		hash = p11.CKM_SHA256
		mgf = p11.CKG_MGF1_SHA256
		prefix = "3031300d060960864801650304020105000420"
	case crypto.SHA384:
		hash = p11.CKM_SHA384
		mgf = p11.CKG_MGF1_SHA384
		prefix = "3041300d060960864801650304020205000430"
	case crypto.SHA512:
		hash = p11.CKM_SHA512
		mgf = p11.CKG_MGF1_SHA512
		prefix = "3051300d060960864801650304020305000440"
	default:
		return nil, fmt.Errorf("unsupported signing hash: %v", h)
	}
	mechanism := p11.NewMechanism(p11.CKM_RSA_PKCS, nil)
	data := digest
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		salt := pss.SaltLength
		if salt == rsa.PSSSaltLengthEqualsHash {
			salt = h.Size()
		}
		if salt == rsa.PSSSaltLengthAuto {
			salt = (s.pub.N.BitLen()-1+7)/8 - h.Size() - 2
		}
		if salt < 0 {
			return nil, fmt.Errorf("invalid PSS salt length")
		}
		mechanism = p11.NewMechanism(p11.CKM_RSA_PKCS_PSS, p11.NewPSSParams(hash, mgf, uint(salt)))
	} else {
		p, _ := hex.DecodeString(prefix)
		data = append(p, digest...)
	}
	if err := s.t.p.SignInit(s.t.session, []*p11.Mechanism{mechanism}, s.key); err != nil {
		return nil, err
	}
	return s.t.p.Sign(s.t.session, data)
}
