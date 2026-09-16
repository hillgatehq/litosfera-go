package main

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

type requestLogKey struct{}
type requestLogContext struct {
	id          uint64
	environment string
}

var requestSequence atomic.Uint64

// Log only known routes: arbitrary paths and query strings may contain secrets.
func logRoute(path string) string {
	switch path {
	case "/api", "/api/sign", "/api/identity/token/checked":
		return path
	}
	return "<unknown>"
}

type loggedResponse struct {
	http.ResponseWriter
	status, bytes int
	outcome       string
}

func (w *loggedResponse) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *loggedResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}
func (w *loggedResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	meta := requestLogContext{requestSequence.Add(1), s.environment}
	r = r.WithContext(context.WithValue(r.Context(), requestLogKey{}, meta))
	rw := &loggedResponse{ResponseWriter: w}
	log.Printf("[IN] id=%d env=%s method=%q path=%q started", meta.id, meta.environment, r.Method, logRoute(r.URL.Path))
	defer func() {
		status := rw.status
		if status == 0 {
			status = http.StatusOK
		}
		outcome := rw.outcome
		if outcome == "" {
			outcome = "ok"
			if status >= 400 {
				outcome = "rejected"
			}
		}
		log.Printf("[IN] id=%d env=%s method=%q path=%q status=%d outcome=%s bytes=%d duration=%s", meta.id, meta.environment, r.Method, logRoute(r.URL.Path), status, outcome, rw.bytes, time.Since(start).Round(time.Millisecond))
	}()
	s.serveHTTP(rw, r)
}
