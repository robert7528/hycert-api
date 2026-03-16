package chain

import (
	"crypto/sha256"
	"crypto/x509"

	"go.uber.org/zap"
)

// RootStore wraps the system root CA pool.
type RootStore struct {
	pool  *x509.CertPool
	roots map[string]*x509.Certificate // fingerprint → cert (for lookup)
	log   *zap.Logger
}

// NewRootStore creates a RootStore backed by the OS system root CA pool.
func NewRootStore(log *zap.Logger) *RootStore {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		log.Warn("failed to load system cert pool, using empty pool", zap.Error(err))
		pool = x509.NewCertPool()
	}

	return &RootStore{
		pool:  pool,
		roots: make(map[string]*x509.Certificate),
		log:   log,
	}
}

// Contains checks if the certificate is in the system root CA pool.
func (s *RootStore) Contains(cert *x509.Certificate) bool {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots: s.pool,
	})
	return err == nil
}

// FindIssuer tries to find the issuer of cert in the system root CA pool.
func (s *RootStore) FindIssuer(cert *x509.Certificate) *x509.Certificate {
	// Use Verify to check if any root in the pool can verify this cert
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots: s.pool,
	})
	if err != nil || len(chains) == 0 {
		return nil
	}
	// The last cert in the first verified chain is the root
	chain := chains[0]
	if len(chain) > 1 {
		return chain[len(chain)-1]
	}
	return nil
}

// Pool returns the underlying CertPool (for use in x509.Verify).
func (s *RootStore) Pool() *x509.CertPool {
	return s.pool
}

func fingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return string(h[:])
}
