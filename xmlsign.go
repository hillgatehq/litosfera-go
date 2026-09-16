package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const dsNS = "http://www.w3.org/2000/09/xmldsig#"
const xaNS = "http://uri.etsi.org/01903/v1.3.2#"
const exc = "http://www.w3.org/2001/10/xml-exc-c14n#"
const shaURI = "http://www.w3.org/2001/04/xmlenc#sha256"
const rsaURI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
const xchgXML = `<Xchg>
   <PyldDesc>
      <ApplSpcfcInf>
         <Sgntr/>
      </ApplSpcfcInf>
   </PyldDesc>
   <Pyld>
   </Pyld>
</Xchg>`

type xmlSigner struct {
	key    crypto.Signer
	cert   *x509.Certificate
	crlRef string
}

func elem(p *etree.Element, name, text string) *etree.Element {
	e := p.CreateElement(name)
	if text != "" {
		e.SetText(text)
	}
	return e
}
func canon(e *etree.Element) ([]byte, error) {
	copy := e.Copy()
	seen := map[string]bool{}
	for p := e; p != nil; p = p.Parent() {
		for _, a := range p.Attr {
			if a.Space == "xmlns" || a.FullKey() == "xmlns" {
				if !seen[a.FullKey()] {
					copy.CreateAttr(a.FullKey(), a.Value)
					seen[a.FullKey()] = true
				}
			}
		}
	}
	return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("").Canonicalize(copy)
}
func digest(e *etree.Element) (string, error) {
	b, err := canon(e)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return base64.StdEncoding.EncodeToString(h[:]), nil
}
func addRef(si *etree.Element, uri, typ, value string, enveloped bool) {
	r := elem(si, "ds:Reference", "")
	r.CreateAttr("URI", uri)
	if typ != "" {
		r.CreateAttr("Type", typ)
	}
	ts := elem(r, "ds:Transforms", "")
	if enveloped {
		elem(ts, "ds:Transform", "").CreateAttr("Algorithm", dsNS+"enveloped-signature")
	}
	elem(ts, "ds:Transform", "").CreateAttr("Algorithm", exc)
	elem(r, "ds:DigestMethod", "").CreateAttr("Algorithm", shaURI)
	elem(r, "ds:DigestValue", value)
}
func (s *xmlSigner) sign(input, typ string, now time.Time) (string, error) {
	if now.Before(s.cert.NotBefore) || now.After(s.cert.NotAfter) {
		return "", fmt.Errorf("signing certificate is outside its validity period")
	}
	if strings.Contains(input, "<!") {
		return "", fmt.Errorf("XML declarations other than processing instructions are unsupported")
	}
	d := etree.NewDocument()
	if err := d.ReadFromString(input); err != nil {
		return "", err
	}
	if d.Root() == nil {
		return "", fmt.Errorf("missing XML root")
	}
	count := 0
	for _, n := range d.Child {
		if _, ok := n.(*etree.Element); ok {
			count++
		}
	}
	if count != 1 {
		return "", fmt.Errorf("expected one XML root")
	}
	root := d.Root()
	if len(root.FindElements(".//Signature")) > 0 {
		return "", fmt.Errorf("input already has Signature")
	}
	var parent *etree.Element
	switch typ {
	case "edoc":
		r := etree.NewElement("EDoc")
		d.SetRoot(r)
		r.AddChild(root)
		root = r
		parent = root
	case "xchg":
		if root.Tag != "Xchg" || root.Space != "" {
			return "", fmt.Errorf("expected Xchg")
		}
		parent = root.FindElement("PyldDesc/ApplSpcfcInf/Sgntr")
		if parent == nil || len(parent.Child) != 0 {
			return "", fmt.Errorf("expected empty Sgntr")
		}
	default:
		return "", fmt.Errorf("unsupported signature type")
	}
	docDigest, err := digest(root)
	if err != nil {
		return "", err
	}
	idBytes := make([]byte, 16)
	if _, err = rand.Read(idBytes); err != nil {
		return "", err
	}
	id := fmt.Sprintf("signature-%x", idBytes)
	pid := "signedproperties-" + id[10:]
	sig := elem(parent, "ds:Signature", "")
	sig.CreateAttr("xmlns:ds", dsNS)
	sig.CreateAttr("Id", id)
	si := elem(sig, "ds:SignedInfo", "")
	elem(si, "ds:CanonicalizationMethod", "").CreateAttr("Algorithm", exc)
	elem(si, "ds:SignatureMethod", "").CreateAttr("Algorithm", rsaURI)
	sv := elem(sig, "ds:SignatureValue", "")
	sv.CreateAttr("Id", id+"-sigvalue")
	ki := elem(sig, "ds:KeyInfo", "")
	ki.CreateAttr("Id", "KeyInfo")
	if typ == "xchg" {
		xd := elem(ki, "ds:X509Data", "")
		elem(xd, "ds:X509Certificate", base64.StdEncoding.EncodeToString(s.cert.Raw))
	}
	obj := elem(sig, "ds:Object", "")
	if s.crlRef != "" {
		elem(obj, "ds:QualifyingPropertiesReference", "").CreateAttr("URI", s.crlRef)
	}
	qp := elem(obj, "xades:QualifyingProperties", "")
	qp.CreateAttr("xmlns:xades", xaNS)
	qp.CreateAttr("xmlns:xades141", "http://uri.etsi.org/01903/v1.4.1#")
	qp.CreateAttr("Target", "#"+id)
	sp := elem(qp, "xades:SignedProperties", "")
	sp.CreateAttr("Id", pid)
	ssp := elem(sp, "xades:SignedSignatureProperties", "")
	elem(ssp, "xades:SigningTime", now.Format(time.RFC3339))
	sc := elem(ssp, "xades:SigningCertificate", "")
	ce := elem(sc, "xades:Cert", "")
	cd := elem(ce, "xades:CertDigest", "")
	elem(cd, "ds:DigestMethod", "").CreateAttr("Algorithm", shaURI)
	h := sha256.Sum256(s.cert.Raw)
	elem(cd, "ds:DigestValue", base64.StdEncoding.EncodeToString(h[:]))
	is := elem(ce, "xades:IssuerSerial", "")
	elem(is, "ds:X509IssuerName", s.cert.Issuer.String())
	elem(is, "ds:X509SerialNumber", s.cert.SerialNumber.String())
	place := elem(ssp, "xades:SignatureProductionPlace", "")
	for _, v := range [][2]string{{"City", "City"}, {"StateOrProvince", "State"}, {"PostalCode", "PostalCode"}, {"CountryName", "Country"}} {
		elem(place, "xades:"+v[0], v[1])
	}
	elem(elem(elem(ssp, "xades:SignerRole", ""), "xades:ClaimedRoles", ""), "xades:ClaimedRole", "Some role")
	uri := ""
	if rid := root.SelectAttrValue("Id", ""); rid != "" {
		uri = "#" + rid
	}
	addRef(si, uri, "", docDigest, true)
	if typ == "xchg" {
		kd, e := digest(ki)
		if e != nil {
			return "", e
		}
		addRef(si, "#KeyInfo", "", kd, false)
	}
	pd, err := digest(sp)
	if err != nil {
		return "", err
	}
	addRef(si, "#"+pid, "http://uri.etsi.org/01903#SignedProperties", pd, false)
	b, err := canon(si)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	signature, err := s.key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("token XML signature: %w", err)
	}
	sv.SetText(base64.StdEncoding.EncodeToString(signature))
	out, err := d.WriteToString()
	return out, err
}

// The browser-facing prototype intentionally accepts only the observed login challenge.
func validateChallenge(input string) error {
	d := etree.NewDocument()
	if strings.Contains(input, "<!") {
		return fmt.Errorf("unsupported XML declaration")
	}
	if err := d.ReadFromString(input); err != nil {
		return err
	}
	r := d.Root()
	if r == nil || r.Tag != "Register" || r.Space != "" || r.SelectAttrValue("ID", "") != "Edoc" || len(r.Attr) != 1 || len(r.ChildElements()) != 0 {
		return fmt.Errorf("expected Register ID='Edoc' login challenge")
	}
	_, err := time.Parse("2006-01-02T15:04:05", r.Text())
	return err
}
