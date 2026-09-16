package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBrowserAPI(t *testing.T) {
	s := &service{environment: "TEST", origin: "https://dstestlitas.lb.lt", signer: testSigner(t)}
	for _, c := range []struct {
		name, method, path, origin, host, body string
		auth                                   bool
		status                                 int
	}{
		{"info", "GET", "/api", s.origin, "localhost:9899", "", true, 200},
		{"preflight", "OPTIONS", "/api/sign", s.origin, "localhost:9899", "", false, 200},
		{"wrong origin", "POST", "/api/sign", "https://evil.example", "localhost:9899", "", true, 403},
		{"wrong host", "GET", "/api", s.origin, "evil.example:9899", "", true, 403},
		{"no auth", "GET", "/api", s.origin, "localhost:9899", "", false, 401},
		{"sign", "POST", "/api/sign", s.origin, "127.0.0.1:9899", `{"request":"<Register ID='Edoc'>2026-09-16T19:59:47</Register>","type":"edoc"}`, true, 200},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, "http://"+c.host+c.path, strings.NewReader(c.body))
			r.Header.Set("Origin", c.origin)
			if c.auth {
				r.SetBasicAuth("user1", "pass1")
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != c.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if c.name == "sign" {
				var v map[string]any
				json.Unmarshal(w.Body.Bytes(), &v)
				if v["success"] != true {
					t.Fatal(w.Body.String())
				}
			}
		})
	}
}
func TestIdentityOverMTLS(t *testing.T) {
	s := testSigner(t)
	pool := x509.NewCertPool()
	pool.AddCert(s.cert)
	var calls []string
	failVerify := false
	failRefresh := false
	bank := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		if len(r.TLS.PeerCertificates) != 1 {
			t.Error("missing client certificate")
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "user1" || p != "pass1" {
			t.Error("wrong basic auth")
		}
		if r.Method != "POST" {
			t.Error("wrong method")
		}
		var data map[string]string
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			t.Error(err)
		}
		switch r.URL.Path {
		case "/idsvc/login":
			b, e := base64.StdEncoding.DecodeString(data["xml"])
			if e != nil || !strings.Contains(string(b), "Xchg") || !strings.Contains(string(b), "ds:X509Certificate") {
				t.Error("missing signed Xchg")
			}
			reply(w, identityReply{true, "access1", "refresh1"})
		case "/idsvc/verify":
			reply(w, identityReply{Success: !failVerify})
		case "/idsvc/refresh":
			if data["refresh"] != "refresh1" {
				t.Error("wrong refresh token")
			}
			reply(w, identityReply{!failRefresh, "access2", "refresh2"})
		default:
			t.Error("unexpected path")
			http.NotFound(w, r)
		}
	}))
	bank.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	bank.StartTLS()
	defer bank.Close()
	transport := bank.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{s.cert.Raw}, PrivateKey: s.key}}
	defer transport.CloseIdleConnections()
	i := &identity{client: &http.Client{Transport: transport, Timeout: time.Second * 5}, base: bank.URL + "/idsvc", user: "user1", password: "pass1", signer: s}
	for n := 0; n < 3; n++ {
		if n == 2 {
			failVerify = true
		}
		got, e := i.checked(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		want := "access1"
		if n == 2 {
			want = "access2"
		}
		if got != want {
			t.Fatal(got)
		}
	}
	if !reflect.DeepEqual(calls, []string{"/idsvc/login", "/idsvc/verify", "/idsvc/verify", "/idsvc/refresh"}) {
		t.Fatal(calls)
	}
	i.access = ""
	i.refresh = "refresh1"
	failRefresh = true
	if got, e := i.checked(context.Background()); e != nil || got != "access1" {
		t.Fatalf("fallback: %s %v", got, e)
	}
}
