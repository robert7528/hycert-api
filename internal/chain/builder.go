package chain

import (
	"crypto/x509"
	"fmt"

	"go.uber.org/zap"
)

// Warning represents a non-fatal issue found during chain building.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

const maxChainDepth = 5

// CertNode represents a certificate in the chain with metadata.
type CertNode struct {
	Certificate *x509.Certificate
	Role        string // leaf | intermediate | root
	Source      string // user_provided | aia_fetched | system_library
}

// ChainResult is the output of BuildChain.
type ChainResult struct {
	Chain       []CertNode
	Complete    bool
	Valid       bool
	RootTrusted bool
	RootSource  string
	Warnings    []Warning
}

// Builder constructs certificate chains.
type Builder struct {
	rootStore *RootStore
	fetcher   *Fetcher
	log       *zap.Logger
}

// NewBuilder creates a new chain builder.
func NewBuilder(rootStore *RootStore, fetcher *Fetcher, log *zap.Logger) *Builder {
	return &Builder{rootStore: rootStore, fetcher: fetcher, log: log}
}

// BuildChain attempts to build a complete certificate chain from leaf to root.
func (b *Builder) BuildChain(leaf *x509.Certificate, intermediates []*x509.Certificate) *ChainResult {
	result := &ChainResult{}

	// Start chain with leaf
	result.Chain = append(result.Chain, CertNode{
		Certificate: leaf,
		Role:        "leaf",
		Source:      "user_provided",
	})

	// Check if leaf is self-signed (rare but possible)
	if isSelfSigned(leaf) {
		result.Chain[0].Role = "root"
		result.Complete = true
		result.Valid = true
		result.RootTrusted = b.rootStore.Contains(leaf)
		if result.RootTrusted {
			result.RootSource = "system_library"
		} else {
			result.RootSource = "user_provided"
		}
		return result
	}

	// Build chain upward
	current := leaf
	visited := make(map[string]bool)
	visited[fingerprint(leaf)] = true

	for depth := 1; depth < maxChainDepth; depth++ {
		// Try to find issuer in user-provided intermediates
		issuer := findIssuer(current, intermediates)
		source := "user_provided"

		// If not found, try AIA chasing
		if issuer == nil {
			aiaURLs := extractAIAURLs(current)
			for _, url := range aiaURLs {
				fetched, err := b.fetcher.Fetch(url)
				if err != nil {
					b.log.Debug("AIA fetch failed", zap.String("url", url), zap.Error(err))
					continue
				}
				for _, cert := range fetched {
					if isIssuerOf(current, cert) {
						issuer = cert
						source = "aia_fetched"
						break
					}
				}
				if issuer != nil {
					break
				}
			}
		}

		if issuer == nil {
			// Check if current cert's issuer is a known root
			if rootCert := b.rootStore.FindIssuer(current); rootCert != nil {
				result.Chain = append(result.Chain, CertNode{
					Certificate: rootCert,
					Role:        "root",
					Source:      "system_library",
				})
				result.Complete = true
				result.Valid = true
				result.RootTrusted = true
				result.RootSource = "system_library"
				return result
			}

			result.Warnings = append(result.Warnings, Warning{
				Code:    "CHAIN_INCOMPLETE",
				Message: fmt.Sprintf("Cannot find issuer for: %s", current.Subject.CommonName),
			})
			break
		}

		// Check for loops
		fp := fingerprint(issuer)
		if visited[fp] {
			result.Warnings = append(result.Warnings, Warning{
				Code:    "CHAIN_LOOP",
				Message: "Certificate chain contains a loop",
			})
			break
		}
		visited[fp] = true

		// Determine role
		role := "intermediate"
		if isSelfSigned(issuer) {
			role = "root"
		}

		result.Chain = append(result.Chain, CertNode{
			Certificate: issuer,
			Role:        role,
			Source:      source,
		})

		if role == "root" {
			result.Complete = true
			result.RootTrusted = b.rootStore.Contains(issuer)
			if result.RootTrusted {
				result.RootSource = "system_library"
			} else {
				result.RootSource = source
			}
			break
		}

		current = issuer
	}

	// Validate chain signatures
	if len(result.Chain) > 1 {
		result.Valid = validateChainSignatures(result.Chain)
	}

	return result
}

// findIssuer looks for the issuer of cert in the candidates.
func findIssuer(cert *x509.Certificate, candidates []*x509.Certificate) *x509.Certificate {
	for _, c := range candidates {
		if isIssuerOf(cert, c) {
			return c
		}
	}
	return nil
}

// isIssuerOf checks if candidate is the issuer of cert using AKID/SKID and subject/issuer DN.
func isIssuerOf(cert, candidate *x509.Certificate) bool {
	// AKID/SKID match (most reliable)
	if len(cert.AuthorityKeyId) > 0 && len(candidate.SubjectKeyId) > 0 {
		if !equalBytes(cert.AuthorityKeyId, candidate.SubjectKeyId) {
			return false
		}
	}

	// Subject/Issuer DN match
	if cert.Issuer.CommonName != candidate.Subject.CommonName {
		return false
	}

	// Verify signature
	err := cert.CheckSignatureFrom(candidate)
	return err == nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

func validateChainSignatures(nodes []CertNode) bool {
	for i := 0; i < len(nodes)-1; i++ {
		err := nodes[i].Certificate.CheckSignatureFrom(nodes[i+1].Certificate)
		if err != nil {
			return false
		}
	}
	return true
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
