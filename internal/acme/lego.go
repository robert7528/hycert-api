package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	legocert "github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/duckdns"
	"github.com/go-acme/lego/v4/registration"
	"go.uber.org/zap"
)

// dnsProviderFactory creates a DNS challenge provider from a JSON config map.
type dnsProviderFactory func(cfg map[string]string) (challenge.Provider, error)

// DNSProviderField describes a credential field for a DNS provider.
type DNSProviderField struct {
	Key    string `json:"key"`    // lego env var name, e.g. "CF_API_TOKEN"
	Label  string `json:"label"`  // human-readable label
	Secret bool   `json:"secret"` // mask input in UI
}

// DNSProviderDef describes a DNS provider for both runtime and UI.
type DNSProviderDef struct {
	Name    string             `json:"name"`
	Label   string             `json:"label"`
	Fields  []DNSProviderField `json:"fields"`
	factory dnsProviderFactory `json:"-"`
}

// dnsProviders is the single source of truth for supported DNS providers.
// To add a new provider:
//  1. Import the provider package
//  2. Add a DNSProviderDef entry here
var dnsProviders = []DNSProviderDef{
	{
		Name:  "cloudflare",
		Label: "Cloudflare",
		Fields: []DNSProviderField{
			{Key: "CF_API_TOKEN", Label: "API Token", Secret: true},
		},
		factory: func(cfg map[string]string) (challenge.Provider, error) {
			c := cloudflare.NewDefaultConfig()
			if v := cfg["CF_API_TOKEN"]; v != "" {
				c.AuthToken = v
			} else if v := cfg["CF_API_KEY"]; v != "" {
				c.AuthKey = v
				c.AuthEmail = cfg["CF_API_EMAIL"]
			}
			return cloudflare.NewDNSProviderConfig(c)
		},
	},
	{
		Name:  "duckdns",
		Label: "DuckDNS",
		Fields: []DNSProviderField{
			{Key: "DUCKDNS_TOKEN", Label: "Token", Secret: true},
		},
		factory: func(cfg map[string]string) (challenge.Provider, error) {
			c := duckdns.NewDefaultConfig()
			c.Token = cfg["DUCKDNS_TOKEN"]
			return duckdns.NewDNSProviderConfig(c)
		},
	},
	{
		Name:   "manual",
		Label:  "Manual",
		Fields: []DNSProviderField{},
	},
}

// dnsProviderMap is built from dnsProviders for O(1) lookup.
var dnsProviderMap map[string]*DNSProviderDef

func init() {
	dnsProviderMap = make(map[string]*DNSProviderDef, len(dnsProviders))
	for i := range dnsProviders {
		dnsProviderMap[dnsProviders[i].Name] = &dnsProviders[i]
	}
}

// GetDNSProviderDefs returns the provider definitions for the UI.
func GetDNSProviderDefs() []DNSProviderDef {
	return dnsProviders
}

// LegoUser implements lego's registration.User interface.
type LegoUser struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *LegoUser) GetEmail() string                        { return u.Email }
func (u *LegoUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *LegoUser) GetPrivateKey() crypto.PrivateKey        { return u.Key }

// LegoClient wraps lego ACME operations.
type LegoClient struct {
	log               *zap.Logger
	httpChallengePort string
}

// NewLegoClient creates a new lego wrapper.
func NewLegoClient(log *zap.Logger, httpChallengePort string) *LegoClient {
	return &LegoClient{log: log, httpChallengePort: httpChallengePort}
}

// GenerateAccountKey generates a new EC P-256 key pair for ACME account registration.
func (lc *LegoClient) GenerateAccountKey() (crypto.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate EC key: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("marshal EC key: %w", err)
	}

	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	}))

	return key, keyPEM, nil
}

// Register registers an ACME account with the given directory URL.
func (lc *LegoClient) Register(user *LegoUser, directoryURL string) (*registration.Resource, error) {
	config := lego.NewConfig(user)
	config.CADirURL = directoryURL
	config.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("create ACME client: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("register ACME account: %w", err)
	}

	return reg, nil
}

// ObtainCertificate requests a new certificate for the given domains.
func (lc *LegoClient) ObtainCertificate(user *LegoUser, directoryURL string, domains []string, challengeType, dnsProvider, dnsConfig, keyType string) (*legocert.Resource, error) {
	config := lego.NewConfig(user)
	config.CADirURL = directoryURL
	config.Certificate.KeyType = lc.parseKeyType(keyType)

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("create ACME client: %w", err)
	}

	if err := lc.setupChallenge(client, challengeType, dnsProvider, dnsConfig); err != nil {
		return nil, err
	}

	request := legocert.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	cert, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("obtain certificate: %w", err)
	}

	return cert, nil
}

// RenewCertificate renews an existing certificate.
func (lc *LegoClient) RenewCertificate(user *LegoUser, directoryURL string, certPEM []byte, challengeType, dnsProvider, dnsConfig, keyType string) (*legocert.Resource, error) {
	config := lego.NewConfig(user)
	config.CADirURL = directoryURL
	config.Certificate.KeyType = lc.parseKeyType(keyType)

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("create ACME client: %w", err)
	}

	if err := lc.setupChallenge(client, challengeType, dnsProvider, dnsConfig); err != nil {
		return nil, err
	}

	certResource := &legocert.Resource{
		Certificate: certPEM,
	}

	renewed, err := client.Certificate.Renew(*certResource, true, false, "")
	if err != nil {
		return nil, fmt.Errorf("renew certificate: %w", err)
	}

	return renewed, nil
}

// ParsePrivateKey parses a PEM-encoded private key.
func (lc *LegoClient) ParsePrivateKey(keyPEM string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// GenerateCertKey generates a new private key for certificate signing based on key type.
func (lc *LegoClient) GenerateCertKey(keyType string) (crypto.PrivateKey, error) {
	switch keyType {
	case "ec256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

func (lc *LegoClient) setupChallenge(client *lego.Client, challengeType, dnsProvider, dnsConfig string) error {
	switch challengeType {
	case "dns-01":
		provider, err := lc.createDNSProvider(dnsProvider, dnsConfig)
		if err != nil {
			return err
		}
		return client.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}))
	case "http-01":
		port := lc.httpChallengePort
		if port == "" {
			port = "80"
		}
		return client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", port))
	default:
		return fmt.Errorf("unsupported challenge type: %s", challengeType)
	}
}

// createDNSProvider creates a DNS-01 challenge provider.
// config is a JSON string with env var key-value pairs, e.g.:
//
//	{"DUCKDNS_TOKEN": "xxx"}
//	{"CF_API_TOKEN": "xxx"}
func (lc *LegoClient) createDNSProvider(providerName, config string) (challenge.Provider, error) {
	if providerName == "manual" {
		return NewManualDNSProvider(lc.log), nil
	}

	def, ok := dnsProviderMap[providerName]
	if !ok || def.factory == nil {
		names := make([]string, 0, len(dnsProviders))
		for _, d := range dnsProviders {
			names = append(names, d.Name)
		}
		return nil, fmt.Errorf("unsupported DNS provider: %q (supported: %v)", providerName, names)
	}

	// Parse config JSON → env var map
	cfg := make(map[string]string)
	if config != "" {
		if err := json.Unmarshal([]byte(config), &cfg); err != nil {
			return nil, fmt.Errorf("parse dns_config: %w (expected {\"ENV_VAR\": \"value\", ...})", err)
		}
	}

	return def.factory(cfg)
}

func (lc *LegoClient) parseKeyType(keyType string) certcrypto.KeyType {
	switch keyType {
	case "ec256":
		return certcrypto.EC256
	case "ec384":
		return certcrypto.EC384
	case "rsa2048":
		return certcrypto.RSA2048
	case "rsa4096":
		return certcrypto.RSA4096
	default:
		return certcrypto.EC256
	}
}

// ManualDNSProvider is a DNS-01 provider that logs instructions for manual TXT record setup.
type ManualDNSProvider struct {
	log *zap.Logger
}

func NewManualDNSProvider(log *zap.Logger) *ManualDNSProvider {
	return &ManualDNSProvider{log: log}
}

func (p *ManualDNSProvider) Present(domain, token, keyAuth string) error {
	p.log.Info("Manual DNS-01 challenge: please create TXT record",
		zap.String("domain", "_acme-challenge."+domain),
		zap.String("value", keyAuth),
	)
	return nil
}

func (p *ManualDNSProvider) CleanUp(domain, token, keyAuth string) error {
	p.log.Info("Manual DNS-01 challenge: please remove TXT record",
		zap.String("domain", "_acme-challenge."+domain),
	)
	return nil
}

func (p *ManualDNSProvider) Timeout() (time.Duration, time.Duration) {
	return 10 * time.Minute, 15 * time.Second
}
