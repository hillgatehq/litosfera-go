package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

type identity struct {
	mu                   sync.Mutex
	client               *http.Client
	base, user, password string
	signer               *xmlSigner
	access, refresh      string
}
type identityRejected struct{ message string }

func (e identityRejected) Error() string { return e.message }

type identityReply struct {
	Success bool   `json:"success"`
	Token   string `json:"token"`
	Refresh string `json:"refresh"`
}

func (i *identity) call(ctx context.Context, path string, payload map[string]string) (identityReply, error) {
	start := time.Now()
	meta, _ := ctx.Value(requestLogKey{}).(requestLogContext)
	status := 0
	outcome := "request_error"
	// Only controlled endpoint metadata is logged; never headers, bodies or raw errors.
	log.Printf("[OUT] id=%d env=%s method=POST endpoint=%q started", meta.id, meta.environment, i.base+path)
	defer func() {
		log.Printf("[OUT] id=%d env=%s method=POST endpoint=%q status=%d outcome=%s duration=%s", meta.id, meta.environment, i.base+path, status, outcome, time.Since(start).Round(time.Millisecond))
	}()

	var out identityReply
	b, err := json.Marshal(payload)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", i.base+path, bytes.NewReader(b))
	if err != nil {
		return out, err
	}
	req.SetBasicAuth(i.user, i.password)
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Charset", "UTF-8")
	outcome = "transport_error"
	res, err := i.client.Do(req)
	if err != nil {
		return out, fmt.Errorf("identity %s: %w", path, err)
	}
	defer res.Body.Close()
	status = res.StatusCode
	outcome = "http_error"
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return out, identityRejected{fmt.Sprintf("identity %s rejected authentication (HTTP %d)", path, res.StatusCode)}
	}
	if res.StatusCode != 200 {
		return out, fmt.Errorf("identity %s: HTTP %d", path, res.StatusCode)
	}
	outcome = "response_read_error"
	data, err := io.ReadAll(io.LimitReader(res.Body, 1024*1024+1))
	if err != nil {
		return out, err
	}
	if len(data) > 1024*1024 {
		outcome = "response_too_large"
		return out, fmt.Errorf("identity response too large")
	}
	outcome = "invalid_json"
	if err = json.Unmarshal(data, &out); err != nil {
		return out, fmt.Errorf("invalid identity JSON")
	}
	if !out.Success {
		outcome = "rejected"
		return out, identityRejected{fmt.Sprintf("identity %s rejected request", path)}
	}
	outcome = "ok"
	return out, nil
}
func (i *identity) checked(ctx context.Context) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.access != "" {
		if _, err := i.call(ctx, "/verify", map[string]string{"token": i.access}); err == nil {
			return i.access, nil
		} else {
			var rejected identityRejected
			if !errors.As(err, &rejected) {
				return "", err
			}
		}
		i.access = ""
	}
	if i.refresh != "" {
		r, err := i.call(ctx, "/refresh", map[string]string{"refresh": i.refresh})
		if err != nil {
			var rejected identityRejected
			if !errors.As(err, &rejected) {
				return "", err
			}
		}
		i.refresh = ""
		if err == nil && r.Token != "" && r.Refresh != "" {
			i.access = r.Token
			i.refresh = r.Refresh
			return i.access, nil
		}
	}
	signed, err := i.signer.sign(xchgXML, "xchg", time.Now())
	if err != nil {
		return "", err
	}
	r, err := i.call(ctx, "/login", map[string]string{"xml": base64.StdEncoding.EncodeToString([]byte(signed))})
	if err != nil {
		return "", err
	}
	if r.Token == "" || r.Refresh == "" {
		return "", fmt.Errorf("identity response missing access or refresh token")
	}
	i.access = r.Token
	i.refresh = r.Refresh
	return i.access, nil
}
