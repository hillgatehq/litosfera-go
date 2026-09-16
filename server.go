package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type service struct {
	environment, origin string
	signer              *xmlSigner
	identity            *identity
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}
func (s *service) serveHTTP(w *loggedResponse, r *http.Request) {
	w.Header().Set("Server", "Litosfera, 1.3.7.5")
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil || (host != "localhost" && host != "127.0.0.1" && host != "::1") {
		http.Error(w, "invalid Host", http.StatusForbidden)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" && origin != s.origin {
		http.Error(w, "origin denied", http.StatusForbidden)
		return
	}
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Add("Vary", "Origin")
	}
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Requested-With,Content-Length,Accept,Origin")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Max-Age", "1800")
		if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
		}
		return
	}
	u, p, ok := r.BasicAuth()
	if !ok || u != "user1" || p != "pass1" {
		w.Header().Set("WWW-Authenticate", `Basic realm="Litosfera"`)
		http.Error(w, "unauthorized", 401)
		return
	}
	var result any
	switch {
	case r.Method == "GET" && r.URL.Path == "/api":
		result = map[string]any{"environment": s.environment, "sysgroup": "LITAS", "service": "Litosfera", "version": "1.3.7.5"}
	case r.Method == "POST" && r.URL.Path == "/api/sign":
		var in struct {
			Request string `json:"request"`
			Type    string `json:"type"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
		err = dec.Decode(&in)
		if err == nil {
			var extra any
			if dec.Decode(&extra) != io.EOF {
				err = fmt.Errorf("expected a single JSON object")
			}
		}
		if err == nil && in.Type != "edoc" {
			err = fmt.Errorf("only edoc login signing is supported")
		}
		if err == nil {
			err = validateChallenge(in.Request)
		}
		if err == nil {
			var signed string
			signed, err = s.signer.sign(in.Request, "edoc", time.Now())
			result = map[string]any{"success": true, "signed": signed}
		}
	case r.Method == "GET" && r.URL.Path == "/api/identity/token/checked":
		var token string
		token, err = s.identity.checked(r.Context())
		result = map[string]any{"success": true, "token": token}
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		w.outcome = "failed"
		reply(w, map[string]any{"success": false, "message": err.Error()})
		return
	}
	reply(w, result)
}
