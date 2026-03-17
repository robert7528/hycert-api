package converter

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/hysp/hycert-api/internal/parser"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/smallstep/pkcs7"
	"go.uber.org/zap"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Supported target formats.
const (
	FormatPEM = "pem"
	FormatDER = "der"
	FormatPFX = "pfx"
	FormatJKS = "jks"
	FormatP7B = "p7b"
)

// ConvertRequest describes what to convert.
type ConvertRequest struct {
	// Raw input data (PEM string or base64-encoded binary)
	Certificate   string
	PrivateKey    string
	InputType     string // auto | pem | der_base64 | pfx_base64
	InputPassword string // password for input PFX (separate from output password)
	Password      string // for PFX/JKS output
	// Parsed intermediates to include
	Intermediates []*x509.Certificate
	TargetFormat  string
	FriendlyName  string
	IncludeChain  bool
}

// ConvertResult is the conversion output.
type ConvertResult struct {
	Data         []byte
	Format       string
	FilenameSugg string
	ChainIncluded bool
	ChainNodes    int
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
	// Parse the input certificate using InputType and InputPassword
	certResult, err := c.parser.ParseWithType([]byte(req.Certificate), req.InputType, req.InputPassword)
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
	case FormatJKS:
		return c.toJKS(leaf, chainCerts, privKey, req.Password)
	case FormatP7B:
		return c.toP7B(leaf, chainCerts)
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

func (c *Converter) toJKS(leaf *x509.Certificate, chain []*x509.Certificate, privKey interface{}, password string) (*ConvertResult, error) {
	if privKey == nil {
		return nil, fmt.Errorf("private key is required for JKS conversion")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required for JKS conversion")
	}

	// Marshal private key to PKCS8 DER
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Build certificate chain: leaf + intermediates
	var certChain []keystore.Certificate
	certChain = append(certChain, keystore.Certificate{
		Type:    "X509",
		Content: leaf.Raw,
	})
	for _, cert := range chain {
		certChain = append(certChain, keystore.Certificate{
			Type:    "X509",
			Content: cert.Raw,
		})
	}

	// Create keystore with PrivateKeyEntry
	ks := keystore.New()
	pke := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       keyDER,
		CertificateChain: certChain,
	}

	if err := ks.SetPrivateKeyEntry("1", pke, []byte(password)); err != nil {
		return nil, fmt.Errorf("failed to set JKS private key entry: %w", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		return nil, fmt.Errorf("failed to encode JKS keystore: %w", err)
	}

	return &ConvertResult{
		Data:          buf.Bytes(),
		Format:        FormatJKS,
		FilenameSugg:  "keystore.jks",
		ChainIncluded: len(chain) > 0,
		ChainNodes:    1 + len(chain),
	}, nil
}

func (c *Converter) toP7B(leaf *x509.Certificate, chain []*x509.Certificate) (*ConvertResult, error) {
	// Collect all certificates (leaf + chain)
	var certs []*x509.Certificate
	certs = append(certs, leaf)
	certs = append(certs, chain...)

	// Build degenerate PKCS#7 SignedData (certificates only, no signature)
	p7bData, err := pkcs7.DegenerateCertificate(rawCerts(certs))
	if err != nil {
		return nil, fmt.Errorf("failed to encode P7B/PKCS#7: %w", err)
	}

	return &ConvertResult{
		Data:          p7bData,
		Format:        FormatP7B,
		FilenameSugg:  "certificate.p7b",
		ChainIncluded: len(chain) > 0,
		ChainNodes:    1 + len(chain),
	}, nil
}

// rawCerts extracts raw DER bytes from x509.Certificate slice.
func rawCerts(certs []*x509.Certificate) []byte {
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	return raw
}

// EncodeBase64 encodes binary data as base64 string.
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
