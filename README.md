# dynamictls

This package provides an `http.RoundTripper` that adds automatic TLS certificate failover to `http.Client`. The rotation happens without losing requests.

## Installation

```bash
go get github.com/vladyslavpavlenko/dynamictls@latest
```

## Usage

```go
import (
    "crypto/tls"
    "net/http"
	
    "github.com/vladyslavpavlenko/dynamictls"
)

// Define certificate loaders
primary := func() (*tls.Certificate, error) {
    cert, err := tls.LoadX509KeyPair("primary.crt", "primary.key")
    return &cert, err
}

secondary := func() (*tls.Certificate, error) {
    cert, err := tls.LoadX509KeyPair("secondary.crt", "secondary.key")
    return &cert, err
}

// Use with HTTP client
client := &http.Client{
    Transport: dynamictls.New(dynamictls.Config{
        PrimaryLoader:   primary,
        SecondaryLoader: secondary,
        BaseTLS: &tls.Config{
            MinVersion: tls.VersionTLS12,
        },
        Threshold: 3, // optional, defaults to 3
    }),
}

resp, err := client.Get("https://example.com")
```

## Configuration

You can configure additional transport options like timeouts and so on:

```go
import (
    "net"
    "time"
)

client := &http.Client{
    Transport: dynamictls.New(dynamictls.Config{
        PrimaryLoader:   primary,
        SecondaryLoader: secondary,
        BaseTLS: &tls.Config{
            MinVersion: tls.VersionTLS12,
        },
        // Custom dialer
        DialContext: (&net.Dialer{
            Timeout:   28 * time.Second,
            KeepAlive: 13 * time.Second,
        }).DialContext,
        // Connection timeouts
        IdleConnTimeout:       28 * time.Second,
    }),
}
```
