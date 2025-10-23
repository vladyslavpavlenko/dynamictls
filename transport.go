package dynamictls

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync/atomic"
)

const threshold = 3

type Loader func() (*tls.Certificate, error)

// Transport is an http.RoundTripper that tries both primary and secondary
// TLS certificates on errors to ensure no request is left unprocessed.
type Transport struct {
	pLoader Loader
	sLoader Loader
	baseTLS *tls.Config

	pFailures atomic.Uint32
	threshold uint32
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
}

func New(cfg Config) *Transport {
	if cfg.Threshold == 0 {
		cfg.Threshold = threshold
	}

	return &Transport{
		pLoader:   cfg.PrimaryLoader,
		sLoader:   cfg.SecondaryLoader,
		baseTLS:   cfg.BaseTLS,
		threshold: cfg.Threshold,
	}
}

// RoundTrip implements http.RoundTripper.
// It tries the primary certificate first, then secondary if primary fails.
// After threshold consecutive failures, it tries secondary first.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	trySecondaryFirst := t.pFailures.Load() >= t.threshold

	if trySecondaryFirst {
		// Try secondary first
		resp, err := t.do(req, t.sLoader)
		if err == nil {
			return resp, nil
		}

		// SecondaryLoader failed, try primary
		resp, err = t.do(req, t.pLoader)
		if err == nil {
			// PrimaryLoader succeeded, reset failure counter
			t.pFailures.Store(0)
			return resp, nil
		}

		return nil, err
	}

	// Try primary first
	resp, err := t.do(req, t.pLoader)
	if err == nil {
		t.pFailures.Store(0)
		return resp, nil
	}

	// PrimaryLoader failed
	t.pFailures.Add(1)

	// Try secondary
	resp, err = t.do(req, t.sLoader)
	if err == nil {
		return resp, nil
	}

	return nil, err
}

func (t *Transport) do(req *http.Request, loader Loader) (*http.Response, error) {
	cert, err := loader()
	if err != nil {
		return nil, fmt.Errorf("loader: %v", err)
	}

	tlsConfig := t.baseTLS.Clone()
	tlsConfig.Certificates = []tls.Certificate{*cert}
	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return cert, nil
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return transport.RoundTrip(req)
}
