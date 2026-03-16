package utility

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hysp/hycert-api/internal/chain"
	"github.com/hysp/hycert-api/internal/parser"
	"go.uber.org/zap"
)

type Service struct {
	parser  *parser.Parser
	builder *chain.Builder
	log     *zap.Logger
}

func NewService(p *parser.Parser, b *chain.Builder, log *zap.Logger) *Service {
	return &Service{parser: p, builder: b, log: log}
}

// Verify parses a certificate and validates its chain.
func (s *Service) Verify(req *VerifyRequest) (*VerifyResponse, error) {
	// Parse leaf certificate
	result, err := s.parser.Parse([]byte(req.Certificate), "")
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	if len(result.Certificates) == 0 {
		return nil, fmt.Errorf("no certificate found in input")
	}

	leaf := result.Certificates[0]

	// Collect user-provided intermediates
	var intermediates []*x509.Certificate
	for _, ci := range req.ChainInput.Intermediates {
		parsed, err := s.parser.Parse([]byte(ci), "")
		if err != nil {
			continue
		}
		intermediates = append(intermediates, parsed.Certificates...)
	}
	// Parse bundle if provided
	if req.ChainInput.Bundle != "" {
		parsed, err := s.parser.Parse([]byte(req.ChainInput.Bundle), "")
		if err == nil {
			intermediates = append(intermediates, parsed.Certificates...)
		}
	}

	// Build chain
	chainResult := s.builder.BuildChain(leaf, intermediates)

	// Check key pair match
	var keyPairMatch *bool
	if req.PrivateKey != "" {
		match, err := checkKeyPair(leaf, req.PrivateKey)
		if err == nil {
			keyPairMatch = &match
		}
	}

	// Build response
	now := time.Now()
	daysRemaining := int(leaf.NotAfter.Sub(now).Hours() / 24)
	if daysRemaining < 0 {
		daysRemaining = 0
	}

	resp := &VerifyResponse{
		Subject: extractSubject(leaf),
		Issuer: IssuerInfo{
			CN: leaf.Issuer.CommonName,
			O:  strings.Join(leaf.Issuer.Organization, ", "),
		},
		Validity: ValidityInfo{
			NotBefore:     leaf.NotBefore,
			NotAfter:      leaf.NotAfter,
			DaysRemaining: daysRemaining,
			IsExpired:     now.After(leaf.NotAfter),
		},
		SANs:        extractSANs(leaf),
		KeyInfo:     extractKeyInfo(leaf),
		Fingerprint: computeFingerprints(leaf),
		Checks: ChecksInfo{
			KeyPairMatch:  keyPairMatch,
			ChainValid:    chainResult.Valid,
			ChainComplete: chainResult.Complete,
			RootTrusted:   chainResult.RootTrusted,
			RootSource:    chainResult.RootSource,
		},
		Warnings: chainResult.Warnings,
	}

	// Build chain nodes
	for i, node := range chainResult.Chain {
		resp.Chain = append(resp.Chain, ChainNode{
			Index:    i,
			Role:     node.Role,
			CN:       node.Certificate.Subject.CommonName,
			IssuerCN: node.Certificate.Issuer.CommonName,
			Source:   node.Source,
		})
	}

	// Add expiry warning
	if daysRemaining < 30 && !resp.Validity.IsExpired {
		resp.Warnings = append(resp.Warnings, chain.Warning{
			Code:    "EXPIRY_WARNING",
			Message: fmt.Sprintf("Certificate expires in %d days", daysRemaining),
		})
	}

	return resp, nil
}

// Parse detects format and extracts certificate details.
func (s *Service) Parse(req *ParseRequest) (*ParseResponse, error) {
	result, err := s.parser.Parse([]byte(req.Input), req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse input: %w", err)
	}

	resp := &ParseResponse{
		Format: string(result.Format),
		HasKey: result.PrivateKey != nil,
	}

	for _, cert := range result.Certificates {
		now := time.Now()
		daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
		if daysRemaining < 0 {
			daysRemaining = 0
		}
		detail := CertDetail{
			Subject:            extractSubject(cert),
			Issuer:             IssuerInfo{CN: cert.Issuer.CommonName, O: strings.Join(cert.Issuer.Organization, ", ")},
			SerialNumber:       cert.SerialNumber.Text(16),
			Validity:           ValidityInfo{NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, DaysRemaining: daysRemaining, IsExpired: now.After(cert.NotAfter)},
			SANs:               extractSANs(cert),
			KeyInfo:            extractKeyInfo(cert),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			Fingerprint:        computeFingerprints(cert),
			IsCA:               cert.IsCA,
			Role:               classifyRole(cert),
		}
		resp.Certificates = append(resp.Certificates, detail)
	}

	return resp, nil
}

// GenerateCSR generates a new private key and CSR.
func (s *Service) GenerateCSR(req *GenerateCSRRequest) (*GenerateCSRResponse, error) {
	keyType := strings.ToUpper(req.KeyType)
	if keyType == "" {
		keyType = "RSA"
	}
	keyBits := req.KeyBits

	var privKey crypto.Signer
	switch keyType {
	case "RSA":
		if keyBits == 0 {
			keyBits = 2048
		}
		if keyBits != 2048 && keyBits != 4096 {
			return nil, fmt.Errorf("unsupported RSA key size: %d (use 2048 or 4096)", keyBits)
		}
		key, err := rsa.GenerateKey(rand.Reader, keyBits)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		privKey = key
	case "EC":
		var curve elliptic.Curve
		switch keyBits {
		case 0, 256:
			keyBits = 256
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported EC curve size: %d (use 256 or 384)", keyBits)
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate EC key: %w", err)
		}
		privKey = key
	default:
		return nil, fmt.Errorf("unsupported key type: %s (use RSA or EC)", keyType)
	}

	// Build CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: req.Domain,
		},
	}
	if req.Subject.O != "" {
		template.Subject.Organization = []string{req.Subject.O}
	}
	if req.Subject.OU != "" {
		template.Subject.OrganizationalUnit = []string{req.Subject.OU}
	}
	if req.Subject.C != "" {
		template.Subject.Country = []string{req.Subject.C}
	}
	if req.Subject.ST != "" {
		template.Subject.Province = []string{req.Subject.ST}
	}
	if req.Subject.L != "" {
		template.Subject.Locality = []string{req.Subject.L}
	}

	// SANs
	allDNS := []string{req.Domain}
	for _, san := range req.SANs {
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			allDNS = append(allDNS, san)
		}
	}
	template.DNSNames = allDNS

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Encode private key to PEM
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return &GenerateCSRResponse{
		CSRPEM:        string(csrPEM),
		PrivateKeyPEM: string(keyPEM),
		KeyType:       keyType,
		KeyBits:       keyBits,
		Warning:       "Save the private_key_pem immediately. It will not be stored by the server.",
	}, nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func extractSubject(cert *x509.Certificate) SubjectInfo {
	return SubjectInfo{
		CN: cert.Subject.CommonName,
		O:  strings.Join(cert.Subject.Organization, ", "),
		C:  strings.Join(cert.Subject.Country, ", "),
		OU: strings.Join(cert.Subject.OrganizationalUnit, ", "),
	}
}

func extractSANs(cert *x509.Certificate) SANInfo {
	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return SANInfo{
		DNS: cert.DNSNames,
		IP:  ips,
	}
}

func extractKeyInfo(cert *x509.Certificate) KeyInfoResp {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return KeyInfoResp{Algorithm: "RSA", Bits: pub.N.BitLen()}
	case *ecdsa.PublicKey:
		return KeyInfoResp{Algorithm: "EC", Bits: pub.Curve.Params().BitSize}
	default:
		return KeyInfoResp{Algorithm: "unknown", Bits: 0}
	}
}

func computeFingerprints(cert *x509.Certificate) FingerprintInfo {
	sha256Hash := sha256.Sum256(cert.Raw)
	sha1Hash := sha1.Sum(cert.Raw)
	return FingerprintInfo{
		SHA256: formatFingerprint(sha256Hash[:]),
		SHA1:   formatFingerprint(sha1Hash[:]),
	}
}

func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

func classifyRole(cert *x509.Certificate) string {
	if cert.IsCA {
		if cert.Subject.CommonName == cert.Issuer.CommonName &&
			cert.AuthorityKeyId != nil &&
			cert.SubjectKeyId != nil &&
			equalBytes(cert.AuthorityKeyId, cert.SubjectKeyId) {
			return "root"
		}
		return "intermediate"
	}
	return "leaf"
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

func checkKeyPair(cert *x509.Certificate, privateKeyPEM string) (bool, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return false, fmt.Errorf("failed to decode private key PEM")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 for RSA
		rsaKey, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err2 != nil {
			// Try EC
			ecKey, err3 := x509.ParseECPrivateKey(block.Bytes)
			if err3 != nil {
				return false, fmt.Errorf("failed to parse private key: %w", err)
			}
			privKey = ecKey
		} else {
			privKey = rsaKey
		}
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if rsaPriv, ok := privKey.(*rsa.PrivateKey); ok {
			return pub.N.Cmp(rsaPriv.N) == 0 && pub.E == rsaPriv.E, nil
		}
		return false, nil
	case *ecdsa.PublicKey:
		if ecPriv, ok := privKey.(*ecdsa.PrivateKey); ok {
			return pub.X.Cmp(ecPriv.X) == 0 && pub.Y.Cmp(ecPriv.Y) == 0, nil
		}
		return false, nil
	default:
		return false, fmt.Errorf("unsupported public key type")
	}
}
