package parser

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

// Format represents the detected certificate format.
type Format string

const (
	FormatPEM     Format = "pem"
	FormatDER     Format = "der"
	FormatPFX     Format = "pfx"
	FormatJKS     Format = "jks"
	FormatUnknown Format = "unknown"
)

// ParseResult contains the parsed certificates and optional private key.
type ParseResult struct {
	Format       Format
	Certificates []*x509.Certificate
	PrivateKey   crypto.PrivateKey
}

// Parser handles certificate parsing and format detection.
type Parser struct{}

// New creates a new Parser.
func New() *Parser {
	return &Parser{}
}

// Parse detects the format and extracts certificates (and optionally a private key).
// inputType can be: "" or "auto" (auto-detect), "pem", "der_base64", "pfx_base64".
// For base64 types, data is expected to be base64-encoded text.
func (p *Parser) Parse(data []byte, password string) (*ParseResult, error) {
	return p.ParseWithType(data, "", password)
}

// ParseWithType parses with an explicit format hint.
func (p *Parser) ParseWithType(data []byte, inputType string, password string) (*ParseResult, error) {
	// Handle base64-encoded binary formats
	switch inputType {
	case "pfx_base64":
		raw, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 PFX data: %w", err)
		}
		return parsePFX(raw, password)
	case "der_base64":
		raw, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 DER data: %w", err)
		}
		return parseDER(raw)
	case "jks_base64":
		raw, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 JKS data: %w", err)
		}
		return parseJKS(raw, password)
	case "p7b_base64":
		raw, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 P7B data: %w", err)
		}
		return parseDER(raw)
	}

	// Auto-detect format
	format := detect(data)

	switch format {
	case FormatPEM:
		return parsePEM(data)
	case FormatDER:
		return parseDER(data)
	case FormatPFX:
		return parsePFX(data, password)
	default:
		// Try PEM first, then DER
		result, err := parsePEM(data)
		if err == nil && len(result.Certificates) > 0 {
			return result, nil
		}
		result, err = parseDER(data)
		if err == nil {
			return result, nil
		}
		return nil, fmt.Errorf("unable to detect or parse certificate format")
	}
}

// detect tries to identify the format of the input data.
func detect(data []byte) Format {
	// Check for PEM header
	if block, _ := pem.Decode(data); block != nil {
		return FormatPEM
	}
	// Check for PFX/PKCS#12 (ASN.1 SEQUENCE containing OID 1.2.840.113549.1.7.1)
	// PFX files start with 0x30 0x82 and contain the PKCS#7 OID
	if isPFX(data) {
		return FormatPFX
	}
	// Check for DER (ASN.1 SEQUENCE tag)
	if len(data) > 2 && data[0] == 0x30 {
		return FormatDER
	}
	return FormatUnknown
}

// isPFX checks if data looks like a PKCS#12/PFX file.
// PFX files are ASN.1 SEQUENCE that contain the PKCS#7 data OID (1.2.840.113549.1.7.1).
func isPFX(data []byte) bool {
	if len(data) < 4 || data[0] != 0x30 {
		return false
	}
	// Try to verify by looking for the PKCS#7 OID bytes: 06 09 2A 86 48 86 F7 0D 01 07 01
	pfxOID := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}
	for i := 0; i+len(pfxOID) <= len(data) && i < 30; i++ {
		match := true
		for j := range pfxOID {
			if data[i+j] != pfxOID[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func parsePEM(data []byte) (*ParseResult, error) {
	result := &ParseResult{Format: FormatPEM}
	rest := data

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			result.Certificates = append(result.Certificates, cert)

		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				result.PrivateKey = key.(crypto.PrivateKey)
			}

		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				result.PrivateKey = key
			}

		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				result.PrivateKey = key
			}
		}
	}

	if len(result.Certificates) == 0 && result.PrivateKey == nil {
		return nil, fmt.Errorf("no certificates or keys found in PEM data")
	}

	return result, nil
}

func parseDER(data []byte) (*ParseResult, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER certificate: %w", err)
	}
	return &ParseResult{
		Format:       FormatDER,
		Certificates: []*x509.Certificate{cert},
	}, nil
}

func parseJKS(data []byte, password string) (*ParseResult, error) {
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte(password)); err != nil {
		return nil, fmt.Errorf("failed to load JKS keystore: %w", err)
	}

	result := &ParseResult{Format: FormatJKS}

	for _, alias := range ks.Aliases() {
		if ks.IsTrustedCertificateEntry(alias) {
			entry, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(entry.Certificate.Content)
			if err != nil {
				continue
			}
			result.Certificates = append(result.Certificates, cert)
		}
		if ks.IsPrivateKeyEntry(alias) {
			entry, err := ks.GetPrivateKeyEntry(alias, []byte(password))
			if err != nil {
				continue
			}
			// Parse certificate chain
			for _, c := range entry.CertificateChain {
				cert, err := x509.ParseCertificate(c.Content)
				if err != nil {
					continue
				}
				result.Certificates = append(result.Certificates, cert)
			}
			// Parse private key
			key, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
			if err == nil {
				result.PrivateKey = key.(crypto.PrivateKey)
			}
		}
	}

	if len(result.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in JKS keystore")
	}

	return result, nil
}

func parsePFX(data []byte, password string) (*ParseResult, error) {
	privKey, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PFX/PKCS#12: %w", err)
	}

	result := &ParseResult{
		Format: FormatPFX,
	}

	if cert != nil {
		result.Certificates = append(result.Certificates, cert)
	}
	result.Certificates = append(result.Certificates, caCerts...)

	if privKey != nil {
		if k, ok := privKey.(crypto.PrivateKey); ok {
			result.PrivateKey = k
		}
	}

	return result, nil
}
