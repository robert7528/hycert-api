package chain

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	fetchTimeout = 5 * time.Second
	cacheTTL     = 24 * time.Hour
)

type cacheEntry struct {
	certs     []*x509.Certificate
	fetchedAt time.Time
}

// Fetcher downloads certificates from AIA URLs with caching.
type Fetcher struct {
	client *http.Client
	cache  sync.Map
	log    *zap.Logger
}

// NewFetcher creates a new AIA fetcher with timeout and in-memory cache.
func NewFetcher(log *zap.Logger) *Fetcher {
	return &Fetcher{
		client: &http.Client{Timeout: fetchTimeout},
		log:    log,
	}
}

// Fetch downloads a certificate from the given URL, using cache when available.
func (f *Fetcher) Fetch(url string) ([]*x509.Certificate, error) {
	// Check cache
	if val, ok := f.cache.Load(url); ok {
		entry := val.(*cacheEntry)
		if time.Since(entry.fetchedAt) < cacheTTL {
			return entry.certs, nil
		}
		f.cache.Delete(url)
	}

	// Validate URL scheme (SSRF prevention)
	if !isAllowedURL(url) {
		return nil, fmt.Errorf("AIA URL scheme not allowed: %s", url)
	}

	f.log.Debug("fetching AIA certificate", zap.String("url", url))

	resp, err := f.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("AIA fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AIA fetch returned status %d", resp.StatusCode)
	}

	// Limit read to 1MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("AIA read failed: %w", err)
	}

	certs, err := parseFetchedCerts(body)
	if err != nil {
		return nil, err
	}

	// Cache result
	f.cache.Store(url, &cacheEntry{certs: certs, fetchedAt: time.Now()})

	return certs, nil
}

func parseFetchedCerts(data []byte) ([]*x509.Certificate, error) {
	// Try PEM first
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			}
		}
	}
	if len(certs) > 0 {
		return certs, nil
	}

	// Try DER
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return []*x509.Certificate{cert}, nil
	}

	return nil, fmt.Errorf("failed to parse fetched certificate (tried PEM and DER)")
}

func isAllowedURL(url string) bool {
	return len(url) > 7 && (url[:7] == "http://" || url[:8] == "https://")
}

// extractAIAURLs extracts Authority Information Access issuer URLs from a certificate.
func extractAIAURLs(cert *x509.Certificate) []string {
	return cert.IssuingCertificateURL
}
