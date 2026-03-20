package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/hysp/hycert-api/internal/chain"
	"github.com/hysp/hycert-api/internal/converter"
	"github.com/hysp/hycert-api/internal/parser"
	"github.com/hysp/hycert-api/internal/utility"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func certCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Certificate utility commands",
	}
	cmd.AddCommand(
		certVerifyCmd(),
		certParseCmd(),
		certConvertCmd(),
		certMergeChainCmd(),
		certDecryptKeyCmd(),
		certGenerateCSRCmd(),
	)
	return cmd
}

// newService creates a utility.Service for CLI use (no DB needed).
func newService() *utility.Service {
	log, _ := zap.NewDevelopment()
	p := parser.New()
	rootStore := chain.NewRootStore(log)
	fetcher := chain.NewFetcher(log)
	builder := chain.NewBuilder(rootStore, fetcher, log)
	conv := converter.New(p, log)
	return utility.NewService(p, builder, conv, log)
}

func readFileArg(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("--file is required")
	}
	return os.ReadFile(path)
}

func printJSON(v interface{}) {
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

// ── verify ──────────────────────────────────────────────────────────────────

func certVerifyCmd() *cobra.Command {
	var file, keyFile, password string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a certificate (chain, expiry, key pair)",
		Example: `  hycert cert verify --file server.pem
  hycert cert verify --file server.pfx --password mypass
  hycert cert verify --file server.pem --key server.key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readFileArg(file)
			if err != nil {
				return err
			}
			req := &utility.VerifyRequest{
				Certificate: string(data),
				Password:    password,
			}
			if keyFile != "" {
				keyData, err := os.ReadFile(keyFile)
				if err != nil {
					return fmt.Errorf("read key file: %w", err)
				}
				req.PrivateKey = string(keyData)
			}
			svc := newService()
			resp, err := svc.Verify(req)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "Certificate file path (required)")
	cmd.Flags().StringVar(&keyFile, "key", "", "Private key file path (optional)")
	cmd.Flags().StringVar(&password, "password", "", "Password for PFX/JKS files")
	return cmd
}

// ── parse ───────────────────────────────────────────────────────────────────

func certParseCmd() *cobra.Command {
	var file, password string
	cmd := &cobra.Command{
		Use:   "parse",
		Short: "Parse and display certificate details",
		Example: `  hycert cert parse --file server.pem
  hycert cert parse --file keystore.jks --password mypass`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readFileArg(file)
			if err != nil {
				return err
			}
			svc := newService()
			resp, err := svc.Parse(&utility.ParseRequest{
				Input:    string(data),
				Password: password,
			})
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "Certificate file path (required)")
	cmd.Flags().StringVar(&password, "password", "", "Password for PFX/JKS files")
	return cmd
}

// ── convert ─────────────────────────────────────────────────────────────────

func certConvertCmd() *cobra.Command {
	var file, keyFile, format, password, inputPassword, output string
	cmd := &cobra.Command{
		Use:   "convert",
		Short: "Convert certificate format",
		Example: `  hycert cert convert --file server.pem --format pfx --password mypass
  hycert cert convert --file server.pfx --input-password old --format pem
  hycert cert convert --file server.pem --format jks --password mypass -o server.jks`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readFileArg(file)
			if err != nil {
				return err
			}
			if format == "" {
				return fmt.Errorf("--format is required (pem, der, pfx, jks, p7b)")
			}
			req := &utility.ConvertRequest{
				Certificate:  string(data),
				TargetFormat: format,
				InputPassword: inputPassword,
			}
			req.Options.Password = password
			if keyFile != "" {
				keyData, err := os.ReadFile(keyFile)
				if err != nil {
					return fmt.Errorf("read key file: %w", err)
				}
				req.PrivateKey = string(keyData)
			}
			svc := newService()
			resp, err := svc.Convert(req)
			if err != nil {
				return err
			}
			if output != "" {
				decoded, _ := base64.StdEncoding.DecodeString(resp.ContentBase64)
				if err := os.WriteFile(output, decoded, 0600); err != nil {
					return fmt.Errorf("write output: %w", err)
				}
				fmt.Printf("Written to %s (%s)\n", output, resp.Format)
			} else {
				fmt.Printf("Format: %s\n", resp.Format)
				fmt.Printf("Filename: %s\n", resp.FilenameSugg)
				fmt.Printf("Chain included: %v\n", resp.ChainIncluded)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "Certificate file path (required)")
	cmd.Flags().StringVar(&keyFile, "key", "", "Private key file path")
	cmd.Flags().StringVar(&format, "format", "", "Target format: pem, der, pfx, jks, p7b (required)")
	cmd.Flags().StringVar(&password, "password", "", "Output password (for PFX/JKS)")
	cmd.Flags().StringVar(&inputPassword, "input-password", "", "Input password (for PFX/JKS source)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	return cmd
}

// ── merge-chain ─────────────────────────────────────────────────────────────

func certMergeChainCmd() *cobra.Command {
	var files []string
	var output string
	cmd := &cobra.Command{
		Use:   "merge-chain",
		Short: "Merge multiple certificates into an ordered chain",
		Example: `  hycert cert merge-chain --files root.cer,uca.cer,server.cer
  hycert cert merge-chain --files root.cer,uca.cer,server.cer -o fullchain.pem`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(files) == 0 {
				return fmt.Errorf("--files is required")
			}
			var certs []string
			for _, f := range files {
				// Support comma-separated and repeated flags
				for _, path := range strings.Split(f, ",") {
					path = strings.TrimSpace(path)
					if path == "" {
						continue
					}
					data, err := os.ReadFile(path)
					if err != nil {
						return fmt.Errorf("read %s: %w", path, err)
					}
					certs = append(certs, string(data))
				}
			}
			svc := newService()
			resp, err := svc.MergeChain(&utility.MergeChainRequest{
				Certificates: certs,
			})
			if err != nil {
				return err
			}
			if output != "" {
				if err := os.WriteFile(output, []byte(resp.PEM), 0600); err != nil {
					return fmt.Errorf("write output: %w", err)
				}
				fmt.Printf("Written %d certificates to %s\n", resp.Count, output)
			} else {
				for _, node := range resp.Chain {
					fmt.Printf("[%d] %s — %s\n", node.Index, node.Role, node.CN)
				}
				fmt.Println("---")
				fmt.Print(resp.PEM)
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&files, "files", nil, "Certificate files (comma-separated or repeated)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	return cmd
}

// ── decrypt-key ─────────────────────────────────────────────────────────────

func certDecryptKeyCmd() *cobra.Command {
	var file, password, output string
	cmd := &cobra.Command{
		Use:   "decrypt-key",
		Short: "Decrypt an encrypted private key to plain PEM",
		Example: `  hycert cert decrypt-key --file encrypted.key --password mypass
  hycert cert decrypt-key --file encrypted.key --password mypass -o decrypted.key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readFileArg(file)
			if err != nil {
				return err
			}
			if password == "" {
				return fmt.Errorf("--password is required")
			}
			svc := newService()
			resp, err := svc.DecryptKey(&utility.DecryptKeyRequest{
				EncryptedKey: string(data),
				Password:     password,
			})
			if err != nil {
				return err
			}
			if output != "" {
				if err := os.WriteFile(output, []byte(resp.PrivateKeyPEM), 0600); err != nil {
					return fmt.Errorf("write output: %w", err)
				}
				fmt.Printf("Written %s %d-bit key to %s\n", resp.KeyType, resp.Bits, output)
			} else {
				fmt.Printf("Key: %s %d-bit\n", resp.KeyType, resp.Bits)
				fmt.Print(resp.PrivateKeyPEM)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "Encrypted key file path (required)")
	cmd.Flags().StringVar(&password, "password", "", "Decryption password (required)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	return cmd
}

// ── generate-csr ────────────────────────────────────────────────────────────

func certGenerateCSRCmd() *cobra.Command {
	var cn, org, ou, country, state, locality, keyType, passphrase, outputDir string
	var sans []string
	var keyBits int
	cmd := &cobra.Command{
		Use:   "generate-csr",
		Short: "Generate a CSR and private key",
		Example: `  hycert cert generate-csr --cn example.com --org "My Corp" --country TW --state "Taipei" --locality "Zhongzheng"
  hycert cert generate-csr --cn *.example.com --sans www.example.com,api.example.com -o ./certs/`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cn == "" {
				return fmt.Errorf("--cn is required")
			}
			req := &utility.GenerateCSRRequest{
				Domain:     cn,
				KeyType:    keyType,
				KeyBits:    keyBits,
				Passphrase: passphrase,
			}
			req.SANs = sans
			req.Subject.O = org
			req.Subject.OU = ou
			req.Subject.C = country
			req.Subject.ST = state
			req.Subject.L = locality

			svc := newService()
			resp, err := svc.GenerateCSR(req)
			if err != nil {
				return err
			}

			if outputDir != "" {
				baseName := strings.ReplaceAll(cn, "*", "_wildcard")
				csrPath := outputDir + "/" + baseName + ".csr"
				keyPath := outputDir + "/" + baseName + ".key"
				if err := os.MkdirAll(outputDir, 0755); err != nil {
					return fmt.Errorf("create output dir: %w", err)
				}
				if err := os.WriteFile(csrPath, []byte(resp.CSRPEM), 0644); err != nil {
					return fmt.Errorf("write CSR: %w", err)
				}
				if err := os.WriteFile(keyPath, []byte(resp.PrivateKeyPEM), 0600); err != nil {
					return fmt.Errorf("write key: %w", err)
				}
				fmt.Printf("CSR: %s\n", csrPath)
				fmt.Printf("Key: %s (%s %d-bit", keyPath, resp.KeyType, resp.KeyBits)
				if resp.KeyEncrypted {
					fmt.Print(", encrypted")
				}
				fmt.Println(")")
			} else {
				fmt.Printf("# CSR (%s %d-bit)\n", resp.KeyType, resp.KeyBits)
				fmt.Print(resp.CSRPEM)
				fmt.Printf("\n# Private Key")
				if resp.KeyEncrypted {
					fmt.Print(" (encrypted)")
				}
				fmt.Println()
				fmt.Print(resp.PrivateKeyPEM)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cn, "cn", "", "Common Name / domain (required)")
	cmd.Flags().StringSliceVar(&sans, "sans", nil, "Subject Alternative Names")
	cmd.Flags().StringVar(&org, "org", "", "Organization (O)")
	cmd.Flags().StringVar(&ou, "ou", "", "Organizational Unit (OU)")
	cmd.Flags().StringVar(&country, "country", "", "Country code (C)")
	cmd.Flags().StringVar(&state, "state", "", "State/Province (ST)")
	cmd.Flags().StringVar(&locality, "locality", "", "Locality/City (L)")
	cmd.Flags().StringVar(&keyType, "key-type", "rsa", "Key type: rsa or ec")
	cmd.Flags().IntVar(&keyBits, "key-bits", 2048, "Key size: 2048/4096 for RSA, 256/384 for EC")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "Encrypt private key with passphrase")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for .csr and .key files")
	return cmd
}
