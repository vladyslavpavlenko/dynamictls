package dynamictls_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vladyslavpavlenko/dynamictls"
)

func TestTransport_RoundTrip(main *testing.T) {
	setUp := func(t *testing.T) *httptest.Server {
		tlsCert, err := generateTLSKeyPair()
		require.NoError(t, err)

		serverTLSConfig := &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
		}

		server := httptest.NewUnstartedServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)
		server.TLS = serverTLSConfig
		server.StartTLS()

		t.Cleanup(server.Close)

		return server
	}

	main.Run("PrimarySucceeds", func(t *testing.T) {
		server := setUp(t)

		pCalled := false
		sCalled := false

		pLoader := func() (*tls.Certificate, error) {
			pCalled = true
			return generateTLSKeyPair()
		}

		sLoader := func() (*tls.Certificate, error) {
			sCalled = true
			return generateTLSKeyPair()
		}

		transport := dynamictls.New(dynamictls.Config{
			PrimaryLoader:   pLoader,
			SecondaryLoader: sLoader,
			BaseTLS: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
			},
		})

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
		require.NoError(t, err)

		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		assert.True(t, pCalled)
		assert.False(t, sCalled)
	})

	main.Run("PrimaryFails_SecondarySucceeds", func(t *testing.T) {
		server := setUp(t)

		pCalled := false
		sCalled := false

		pLoader := func() (*tls.Certificate, error) {
			pCalled = true
			return nil, errors.New("pLoader certificate error")
		}

		sLoader := func() (*tls.Certificate, error) {
			sCalled = true
			return generateTLSKeyPair()
		}

		transport := dynamictls.New(dynamictls.Config{
			PrimaryLoader:   pLoader,
			SecondaryLoader: sLoader,
			BaseTLS: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
			},
		})

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
		require.NoError(t, err)

		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		assert.True(t, pCalled)
		assert.True(t, sCalled)
	})

	main.Run("BothFail", func(t *testing.T) {
		server := setUp(t)

		pErr := errors.New("ploader error")
		sErr := errors.New("sloader error")

		pLoader := func() (*tls.Certificate, error) {
			return nil, pErr
		}

		sLoader := func() (*tls.Certificate, error) {
			return nil, sErr
		}

		transport := dynamictls.New(dynamictls.Config{
			PrimaryLoader:   pLoader,
			SecondaryLoader: sLoader,
			BaseTLS: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
			},
		})

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
		require.NoError(t, err)

		_, err = transport.RoundTrip(req)
		require.EqualError(t, err, "loader: sloader error")
	})

	main.Run("AlwaysTriesBothCerts", func(t *testing.T) {
		server := setUp(t)

		pCallCount := 0
		sCallCount := 0

		pLoader := func() (*tls.Certificate, error) {
			pCallCount++
			return nil, errors.New("pLoader failed")
		}

		sLoader := func() (*tls.Certificate, error) {
			sCallCount++
			return generateTLSKeyPair()
		}

		transport := dynamictls.New(dynamictls.Config{
			PrimaryLoader:   pLoader,
			SecondaryLoader: sLoader,
			BaseTLS: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
			},
		})

		req1, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
		require.NoError(t, err)
		resp1, err := transport.RoundTrip(req1)
		require.NoError(t, err)
		require.NoError(t, resp1.Body.Close())

		req2, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
		require.NoError(t, err)
		resp2, err := transport.RoundTrip(req2)
		require.NoError(t, err)
		require.NoError(t, resp2.Body.Close())

		assert.Equal(t, 2, pCallCount)
		assert.Equal(t, 2, sCallCount)
	})

	main.Run("SwitchesToSecondaryFirstAfterThreshold", func(t *testing.T) {
		server := setUp(t)

		pCallCount := 0
		sCallCount := 0
		callOrder := []string{}

		pLoader := func() (*tls.Certificate, error) {
			pCallCount++
			callOrder = append(callOrder, "pLoader")
			return nil, errors.New("pLoader failed")
		}

		sLoader := func() (*tls.Certificate, error) {
			sCallCount++
			callOrder = append(callOrder, "sLoader")
			return generateTLSKeyPair()
		}

		transport := dynamictls.New(dynamictls.Config{
			PrimaryLoader:   pLoader,
			SecondaryLoader: sLoader,
			BaseTLS: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
			},
		})

		for range 3 {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
			require.NoError(t, err)
			resp, err := transport.RoundTrip(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
		}

		callOrder = nil

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		assert.Equal(t, []string{"sLoader"}, callOrder)
		assert.Equal(t, 3, pCallCount)
		assert.Equal(t, 4, sCallCount)
	})

	main.Run("ResetsFailureCounterOnPrimarySuccess", func(t *testing.T) {
		server := setUp(t)

		pCallCount := 0

		pLoader := func() (*tls.Certificate, error) {
			pCallCount++
			if pCallCount <= 2 {
				return nil, errors.New("pLoader failed")
			}
			return generateTLSKeyPair()
		}

		sLoader := func() (*tls.Certificate, error) {
			return generateTLSKeyPair()
		}

		transport := dynamictls.New(dynamictls.Config{
			PrimaryLoader:   pLoader,
			SecondaryLoader: sLoader,
			BaseTLS: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
			},
		})

		for i := 0; i < 2; i++ {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
			require.NoError(t, err)
			resp, err := transport.RoundTrip(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
		}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	})

	main.Run("CustomTransportOptions", func(t *testing.T) {
		server := setUp(t)

		customDialerCalled := false
		customDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
			customDialerCalled = true
			return (&net.Dialer{
				Timeout:   28 * time.Second,
				KeepAlive: 13 * time.Second,
			}).DialContext(ctx, network, addr)
		}

		pLoader := func() (*tls.Certificate, error) {
			return generateTLSKeyPair()
		}

		sLoader := func() (*tls.Certificate, error) {
			return generateTLSKeyPair()
		}

		transport := dynamictls.New(dynamictls.Config{
			PrimaryLoader:   pLoader,
			SecondaryLoader: sLoader,
			BaseTLS:         &tls.Config{InsecureSkipVerify: true},
			DialContext:     customDialer,
			IdleConnTimeout: 28 * time.Second,
		})

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
		require.NoError(t, err)

		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		assert.True(t, customDialerCalled)
	})
}
