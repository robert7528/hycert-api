package parser

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Format represents the detected certificate format.
type Format string

const (
	FormatPEM     Format = "pem"
	FormatDER     Format = "der"
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
func (p *Parser) Parse(data []byte, password string) (*ParseResult, error) {
	format := detect(data)

	switch format {
	case FormatPEM:
		return parsePEM(data)
	case FormatDER:
		return parseDER(data)
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
	// Check for DER (ASN.1 SEQUENCE tag)
	if len(data) > 2 && data[0] == 0x30 {
		return FormatDER
	}
	return FormatUnknown
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
