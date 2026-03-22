package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	"github.com/go-acme/lego/v4/registration"
	"go.uber.org/zap"
)

// LegoUser implements lego's registration.User interface.
type LegoUser struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *LegoUser) GetEmail() string                        { return u.Email }
func (u *LegoUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *LegoUser) GetPrivateKey() crypto.PrivateKey         { return u.Key }

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

	// Set up challenge provider
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

func (lc *LegoClient) createDNSProvider(provider, config string) (challenge.Provider, error) {
	switch provider {
	case "cloudflare":
		return cloudflare.NewDNSProviderConfig(lc.parseCloudflareConfig(config))
	case "manual":
		return NewManualDNSProvider(lc.log), nil
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s (supported: cloudflare, manual)", provider)
	}
}


func (lc *LegoClient) parseCloudflareConfig(config string) *cloudflare.Config {
	cfg := cloudflare.NewDefaultConfig()
	// Config is a JSON string with "api_token" field.
	// The actual parsing is handled by environment variable injection
	// through lego's standard mechanism, or via the config struct.
	//
	// For now, set the API token from the JSON config.
	// In production, credentials come from Tink-encrypted dns_config_enc.
	if config != "" {
		// Simple extraction: config is expected to be the API token directly
		// or a JSON {"api_token": "..."} — service layer handles parsing.
		cfg.AuthToken = config
	}
	return cfg
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
