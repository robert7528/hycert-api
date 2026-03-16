package converter

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/hysp/hycert-api/internal/parser"
	"go.uber.org/zap"
	"software.sslmate.com/src/go-pkcs12"
)

// Supported target formats.
const (
	FormatPEM = "pem"
	FormatDER = "der"
	FormatPFX = "pfx"
)

// ConvertRequest describes what to convert.
type ConvertRequest struct {
	// Raw input data (PEM string or base64-encoded binary)
	Certificate string
	PrivateKey  string
	Password    string // for PFX/JKS output or input
	// Parsed intermediates to include
	Intermediates []*x509.Certificate
	TargetFormat  string
	FriendlyName  string
	IncludeChain  bool
}

// ConvertResult is the conversion output.
type ConvertResult struct {
	Data             []byte
	Format           string
	FilenameSugg     string
	ChainIncluded    bool
	ChainNodes       int
}

// Converter handles certificate format conversions.
type Converter struct {
	parser *parser.Parser
	log    *zap.Logger
}

// New creates a new Converter.
func New(p *parser.Parser, log *zap.Logger) *Converter {
	return &Converter{parser: p, log: log}
}

// Convert performs the format conversion.
func (c *Converter) Convert(req *ConvertRequest) (*ConvertResult, error) {
	// Parse the input certificate
	certResult, err := c.parser.Parse([]byte(req.Certificate), req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	if len(certResult.Certificates) == 0 {
		return nil, fmt.Errorf("no certificate found in input")
	}

	leaf := certResult.Certificates[0]

	// Collect chain certs
	var chainCerts []*x509.Certificate
	if req.IncludeChain {
		// From input (if bundle)
		if len(certResult.Certificates) > 1 {
			chainCerts = certResult.Certificates[1:]
		}
		// From explicitly provided intermediates
		chainCerts = append(chainCerts, req.Intermediates...)
	}

	// Parse private key if provided
	privKey := certResult.PrivateKey
	if privKey == nil && req.PrivateKey != "" {
		keyResult, err := c.parser.Parse([]byte(req.PrivateKey), "")
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		privKey = keyResult.PrivateKey
	}

	switch req.TargetFormat {
	case FormatPEM:
		return c.toPEM(leaf, chainCerts, privKey)
	case FormatDER:
		return c.toDER(leaf)
	case FormatPFX:
		return c.toPFX(leaf, chainCerts, privKey, req.Password, req.FriendlyName)
	default:
		return nil, fmt.Errorf("unsupported target format: %s", req.TargetFormat)
	}
}

func (c *Converter) toPEM(leaf *x509.Certificate, chain []*x509.Certificate, privKey interface{}) (*ConvertResult, error) {
	var out []byte

	// Leaf cert
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})...)

	// Chain certs
	for _, cert := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}

	// Private key (if available)
	if privKey != nil {
		keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	}

	return &ConvertResult{
		Data:          out,
		Format:        FormatPEM,
		FilenameSugg:  "certificate.pem",
		ChainIncluded: len(chain) > 0,
		ChainNodes:    1 + len(chain),
	}, nil
}

func (c *Converter) toDER(leaf *x509.Certificate) (*ConvertResult, error) {
	return &ConvertResult{
		Data:          leaf.Raw,
		Format:        FormatDER,
		FilenameSugg:  "certificate.der",
		ChainIncluded: false,
		ChainNodes:    1,
	}, nil
}

func (c *Converter) toPFX(leaf *x509.Certificate, chain []*x509.Certificate, privKey interface{}, password, friendlyName string) (*ConvertResult, error) {
	if privKey == nil {
		return nil, fmt.Errorf("private key is required for PFX conversion")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required for PFX conversion")
	}

	pfxData, err := pkcs12.Modern.Encode(privKey, leaf, chain, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PFX: %w", err)
	}

	return &ConvertResult{
		Data:          pfxData,
		Format:        FormatPFX,
		FilenameSugg:  "certificate.pfx",
		ChainIncluded: len(chain) > 0,
		ChainNodes:    1 + len(chain),
	}, nil
}

// EncodeBase64 encodes binary data as base64 string.
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
