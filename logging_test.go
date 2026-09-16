package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRequestLogging(t *testing.T) {
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	s := &service{environment: "TEST", origin: "https://dstestlitas.lb.lt"}
	r := httptest.NewRequest("POST", "http://localhost:9899/api/sign?token=QUERY_SECRET", strings.NewReader(`{"request":"BODY_SECRET","type":"unsupported"}`))
	r.SetBasicAuth("user1", "pass1")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	i := &identity{base: "https://dstestlitas.lb.lt/idsvc", user: "user1", password: "PASSWORD_SECRET", client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true,"token":"TOKEN_SECRET","refresh":"REFRESH_SECRET"}`)), Header: make(http.Header)}, nil
	})}}
	ctx := context.WithValue(context.Background(), requestLogKey{}, requestLogContext{42, "TEST"})
	if _, err := i.call(ctx, "/login", map[string]string{"xml": "XML_SECRET"}); err != nil {
		t.Fatal(err)
	}
	i.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("ERROR_SECRET") })
	if _, err := i.call(ctx, "/verify", map[string]string{"token": "TOKEN_SECRET"}); err == nil {
		t.Fatal("expected failure")
	}
	text := logs.String()
	for _, want := range []string{"[IN]", "env=TEST", "status=200 outcome=failed", "[OUT] id=42", "/idsvc/login", "outcome=ok", "outcome=transport_error", "duration="} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	for _, secret := range []string{"QUERY_SECRET", "BODY_SECRET", "PASSWORD_SECRET", "TOKEN_SECRET", "REFRESH_SECRET", "XML_SECRET", "ERROR_SECRET", "Authorization"} {
		if strings.Contains(text, secret) {
			t.Errorf("logged secret %s", secret)
		}
	}
}
