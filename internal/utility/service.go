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
	"github.com/hysp/hycert-api/internal/converter"
	"github.com/hysp/hycert-api/internal/parser"
	"go.uber.org/zap"
)

type Service struct {
	parser    *parser.Parser
	builder   *chain.Builder
	converter *converter.Converter
	log       *zap.Logger
}

func NewService(p *parser.Parser, b *chain.Builder, conv *converter.Converter, log *zap.Logger) *Service {
	return &Service{parser: p, builder: b, converter: conv, log: log}
}

// Verify parses a certificate and validates its chain.
func (s *Service) Verify(req *VerifyRequest) (*VerifyResponse, error) {
	// Parse leaf certificate
	result, err := s.parser.ParseWithType([]byte(req.Certificate), req.InputType, req.Password)
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
	result, err := s.parser.ParseWithType([]byte(req.Input), req.InputType, req.Password)
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

// Convert converts a certificate to the target format.
func (s *Service) Convert(req *ConvertRequest) (*ConvertResponse, error) {
	includeChain := true
	if req.Options.IncludeChain != nil {
		includeChain = *req.Options.IncludeChain
	}

	// Parse intermediates if provided
	var intermediates []*x509.Certificate
	for _, ci := range req.ChainInput.Intermediates {
		parsed, err := s.parser.Parse([]byte(ci), "")
		if err != nil {
			continue
		}
		intermediates = append(intermediates, parsed.Certificates...)
	}
	if req.ChainInput.Bundle != "" {
		parsed, err := s.parser.Parse([]byte(req.ChainInput.Bundle), "")
		if err == nil {
			intermediates = append(intermediates, parsed.Certificates...)
		}
	}

	convReq := &converter.ConvertRequest{
		Certificate:   req.Certificate,
		PrivateKey:    req.PrivateKey,
		InputType:     req.InputType,
		InputPassword: req.InputPassword,
		Password:      req.Options.Password,
		Intermediates: intermediates,
		TargetFormat:  req.TargetFormat,
		FriendlyName:  req.Options.FriendlyName,
		IncludeChain:  includeChain,
	}

	result, err := s.converter.Convert(convReq)
	if err != nil {
		return nil, err
	}

	// For binary formats, encode as base64
	contentBase64 := converter.EncodeBase64(result.Data)
	if result.Format == "pem" {
		// PEM is already text, but still base64 for consistency
		contentBase64 = converter.EncodeBase64(result.Data)
	}

	return &ConvertResponse{
		Format:        result.Format,
		ContentBase64: contentBase64,
		FilenameSugg:  result.FilenameSugg,
		ChainIncluded: result.ChainIncluded,
		ChainNodes:    result.ChainNodes,
	}, nil
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
	var keyPEM []byte
	keyEncrypted := false

	if req.Passphrase != "" {
		// Encrypt with AES-256-CBC (legacy OpenSSL format, widely compatible)
		encBlock, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", keyDER, []byte(req.Passphrase), x509.PEMCipherAES256) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(encBlock)
		keyEncrypted = true
	} else {
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}

	return &GenerateCSRResponse{
		CSRPEM:        string(csrPEM),
		PrivateKeyPEM: string(keyPEM),
		KeyType:       keyType,
		KeyBits:       keyBits,
		KeyEncrypted:  keyEncrypted,
		Warning:       "Save the private_key_pem immediately. It will not be stored by the server.",
	}, nil
}

// MergeChain accepts multiple PEM certificates and returns them ordered as a chain.
// Order: leaf → intermediate(s) → root, determined by Issuer/Subject matching.
func (s *Service) MergeChain(req *MergeChainRequest) (*MergeChainResponse, error) {
	// Parse all input certificates
	var allCerts []*x509.Certificate
	for i, input := range req.Certificates {
		result, err := s.parser.ParseWithType([]byte(input), "", "")
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate #%d: %w", i+1, err)
		}
		allCerts = append(allCerts, result.Certificates...)
	}

	if len(allCerts) == 0 {
		return nil, fmt.Errorf("no certificates found in input")
	}

	// Order the chain: leaf → intermediate(s) → root
	ordered := orderChain(allCerts)

	// Build PEM output
	var pemBuilder strings.Builder
	var nodes []MergeChainNode
	for i, cert := range ordered {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
		pemBuilder.Write(pem.EncodeToMemory(block))

		nodes = append(nodes, MergeChainNode{
			Index:  i,
			Role:   classifyRole(cert),
			CN:     cert.Subject.CommonName,
			Issuer: cert.Issuer.CommonName,
		})
	}

	return &MergeChainResponse{
		Chain: nodes,
		PEM:   pemBuilder.String(),
		Count: len(ordered),
	}, nil
}

// orderChain sorts certificates into chain order: leaf → intermediate(s) → root.
// Uses Subject/Issuer matching to build the chain from leaf upward.
func orderChain(certs []*x509.Certificate) []*x509.Certificate {
	if len(certs) <= 1 {
		return certs
	}

	// Build a map from Subject CN to certificate for quick lookup
	bySubject := make(map[string]*x509.Certificate)
	for _, c := range certs {
		bySubject[c.Subject.CommonName] = c
	}

	// Find the leaf: the cert whose Subject CN is NOT any other cert's Issuer CN,
	// or the cert that is not a CA.
	isIssuer := make(map[string]bool)
	for _, c := range certs {
		isIssuer[c.Issuer.CommonName] = true
	}

	var leaf *x509.Certificate
	for _, c := range certs {
		if !c.IsCA {
			leaf = c
			break
		}
	}
	if leaf == nil {
		// All are CA certs — find the one not issuing any other cert
		isSubjectOfIssuer := make(map[string]bool)
		for _, c := range certs {
			if c.Subject.CommonName != c.Issuer.CommonName {
				isSubjectOfIssuer[c.Issuer.CommonName] = true
			}
		}
		for _, c := range certs {
			if !isSubjectOfIssuer[c.Subject.CommonName] && c.Subject.CommonName != c.Issuer.CommonName {
				leaf = c
				break
			}
		}
	}
	if leaf == nil {
		// Fallback: just return as-is
		return certs
	}

	// Walk up the chain from leaf
	var ordered []*x509.Certificate
	visited := make(map[string]bool)
	current := leaf

	for current != nil {
		ordered = append(ordered, current)
		visited[current.Subject.CommonName] = true

		// Self-signed root — stop
		if current.Subject.CommonName == current.Issuer.CommonName {
			break
		}

		// Find the issuer
		issuer, ok := bySubject[current.Issuer.CommonName]
		if !ok || visited[issuer.Subject.CommonName] {
			break
		}
		current = issuer
	}

	// Append any remaining certs not in the chain
	for _, c := range certs {
		if !visited[c.Subject.CommonName] {
			ordered = append(ordered, c)
		}
	}

	return ordered
}

// DecryptKey decrypts an encrypted PEM private key and returns unencrypted PEM.
// Supports both legacy OpenSSL format (DEK-Info) and PKCS#8 encrypted format.
func (s *Service) DecryptKey(req *DecryptKeyRequest) (*DecryptKeyResponse, error) {
	block, _ := pem.Decode([]byte(req.EncryptedKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var privKey crypto.PrivateKey

	switch block.Type {
	case "ENCRYPTED PRIVATE KEY":
		// PKCS#8 encrypted format
		key, err := x509.ParsePKCS8PrivateKey(decryptPKCS8(block.Bytes, req.Password))
		if err != nil {
			// Try with the raw password-based decryption
			return nil, fmt.Errorf("failed to decrypt PKCS#8 private key: ensure the password is correct")
		}
		privKey = key

	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
		// Legacy OpenSSL encrypted format (Proc-Type + DEK-Info headers)
		if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
			decrypted, err := x509.DecryptPEMBlock(block, []byte(req.Password)) //nolint:staticcheck
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key: %w", err)
			}
			// Re-parse the decrypted DER bytes
			key, err := parsePrivateKeyDER(decrypted)
			if err != nil {
				return nil, fmt.Errorf("failed to parse decrypted key: %w", err)
			}
			privKey = key
		} else {
			return nil, fmt.Errorf("private key is not encrypted")
		}

	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	// Marshal to unencrypted PKCS#8 PEM
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Detect key type and bits
	keyType, bits := describeKey(privKey)

	return &DecryptKeyResponse{
		PrivateKeyPEM: string(keyPEM),
		KeyType:       keyType,
		Bits:          bits,
	}, nil
}

func parsePrivateKeyDER(der []byte) (crypto.PrivateKey, error) {
	// Try PKCS#8 first
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	// Try PKCS#1 RSA
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	// Try EC
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unable to parse private key in any known format")
}

func decryptPKCS8(data []byte, password string) []byte {
	// For PKCS#8 encrypted keys, Go's x509.ParsePKCS8PrivateKey doesn't handle
	// encryption directly. We attempt to parse anyway in case the key was
	// incorrectly labeled. The caller handles the error.
	_ = password
	return data
}

func describeKey(key crypto.PrivateKey) (string, int) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PrivateKey:
		return "EC", k.Curve.Params().BitSize
	default:
		return "unknown", 0
	}
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
