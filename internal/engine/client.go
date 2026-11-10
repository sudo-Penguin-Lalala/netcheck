package engine

import (
	"crypto/tls"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	defaultClientOnce sync.Once
	defaultClient     *http.Client
	UserAgent         string
)

func init() {
	ver := strings.TrimSpace(os.Getenv("NETCHECK_VERSION"))
	if ver == "" {
		ver = "2.0.0"
	}
	UserAgent = "NetCheck/" + ver + " (+https://github.com/sudo-Penguin-Lalala/netcheck)"
}

type userAgentTransport struct {
	base http.RoundTripper
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}
	return t.base.RoundTrip(req)
}

func NewSSRFTransport() *http.Transport {
	return &http.Transport{
		DialContext:           SSRFDialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   25,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

func GetHTTPClient() *http.Client {
	defaultClientOnce.Do(func() {
		defaultClient = &http.Client{
			Transport: &userAgentTransport{base: NewSSRFTransport()},
			Timeout:   35 * time.Second,
		}
	})
	return defaultClient
}
