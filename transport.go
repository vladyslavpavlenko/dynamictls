package dynamictls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const threshold = 3

type Loader func() (*tls.Certificate, error)

type Transport struct {
	pLoader Loader
	sLoader Loader
	baseTLS *tls.Config

	pFailures atomic.Uint32
	threshold uint32

	pTransport atomic.Pointer[http.Transport]
	sTransport atomic.Pointer[http.Transport]
	mu         sync.RWMutex

	// Transport configuration
	dialContext     func(ctx context.Context, network, addr string) (net.Conn, error)
	idleConnTimeout time.Duration
}

type Config struct {
	// PrimaryLoader is the primary certificate loader.
	PrimaryLoader Loader

	// SecondaryLoader is the secondary certificate loader.
	SecondaryLoader Loader

	// BaseTLS is the base TLS configuration.
	BaseTLS *tls.Config

	// Threshold is the number of consecutive failures before a secondary
	// certificate is tried. The default is 3.
	Threshold uint32

	// DialContext specifies the dial function for creating unencrypted TCP connections.
	// If nil, the default dialer is used.
	// By default, inherited from [http.DefaultTransport].
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// IdleConnTimeout is the maximum amount of time an idle (keep-alive) connection
	// will remain idle before closing itself.
	// Zero means no limit.
	// By default, inherited from [http.DefaultTransport].
	IdleConnTimeout time.Duration
}

func New(cfg Config) *Transport {
	if cfg.Threshold == 0 {
		cfg.Threshold = threshold
	}

	return &Transport{
		pLoader:         cfg.PrimaryLoader,
		sLoader:         cfg.SecondaryLoader,
		baseTLS:         cfg.BaseTLS,
		threshold:       cfg.Threshold,
		dialContext:     cfg.DialContext,
		idleConnTimeout: cfg.IdleConnTimeout,
	}
}

// RoundTrip implements http.RoundTripper.
// It tries the primary certificate first, then secondary if primary fails.
// After threshold consecutive failures, it tries secondary first.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	trySecondaryFirst := t.pFailures.Load() >= t.threshold

	if trySecondaryFirst {
		// Try secondary first
		resp, err := t.do(req, t.sLoader, &t.sTransport)
		if err == nil {
			return resp, nil
		}

		// SecondaryLoader failed, try primary
		resp, err = t.do(req, t.pLoader, &t.pTransport)
		if err == nil {
			// PrimaryLoader succeeded, reset failure counter
			t.pFailures.Store(0)
			return resp, nil
		}
		return nil, err
	}

	// Try primary first
	resp, err := t.do(req, t.pLoader, &t.pTransport)
	if err == nil {
		t.pFailures.Store(0)
		return resp, nil
	}

	// PrimaryLoader failed
	t.pFailures.Add(1)
	return t.do(req, t.sLoader, &t.sTransport)
}

func (t *Transport) do(req *http.Request, l Loader, c *atomic.Pointer[http.Transport]) (*http.Response, error) {
	transport := c.Load()
	if transport != nil {
		return transport.RoundTrip(req)
	}

	t.mu.Lock()

	transport = c.Load()
	if transport != nil {
		t.mu.Unlock()
		return transport.RoundTrip(req)
	}

	cert, err := l()
	if err != nil {
		t.mu.Unlock()
		return nil, fmt.Errorf("load certificate: %w", err)
	}

	var baseTLS *tls.Config
	if t.baseTLS != nil {
		baseTLS = t.baseTLS.Clone()
	} else {
		baseTLS = &tls.Config{}
	}

	baseTLS.Certificates = []tls.Certificate{*cert}

	transport = http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = baseTLS

	if t.dialContext != nil {
		transport.DialContext = t.dialContext
	}
	if t.idleConnTimeout != 0 {
		transport.IdleConnTimeout = t.idleConnTimeout
	}

	c.Store(transport)
	t.mu.Unlock()

	return transport.RoundTrip(req)
}

// RefreshCertificates forces a refresh of both certificates on the next request
func (t *Transport) RefreshCertificates() {
	if old := t.pTransport.Swap(nil); old != nil {
		old.CloseIdleConnections()
	}
	if old := t.sTransport.Swap(nil); old != nil {
		old.CloseIdleConnections()
	}
}
