package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/google/go-tpm/tpmutil"
	gcptpmcredential "github.com/salrashid123/gcp-adc-tpm"
)

const (
	parent_pass_var = "TPM_PARENT_AUTH"
	key_pass_var    = "TPM_KEY_AUTH"
)

var (
	// common options
	tpmPath          = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81010002, "Handle value")
	keyfilepath      = flag.String("keyfilepath", "", "TPM Encrypted KeyFile")
	parentPass       = flag.String("parentPass", "", "Passphrase for the owner handle (will use TPM_PARENT_AUTH env var)")
	keyPass          = flag.String("keyPass", "", "Passphrase for the key handle (will use TPM_KEY_AUTH env var)")
	pcrs             = flag.String("pcrs", "", "PCR Bound value (increasing order, comma separated)")
	expireIn         = flag.Int("expireIn", 3600, "Token expires in seconds")
	scopes           = flag.String("scopes", "https://www.googleapis.com/auth/cloud-platform", "comma separated scopes")
	useOauthToken    = flag.Bool("useOauthToken", false, "Use oauth2 token instead of jwtAccessToken (default: false)")
	useEKParent      = flag.Bool("useEKParent", false, "Use endorsement RSAKey as parent (not h2) (default: false)")

	// oauth options
	identityToken   = flag.Bool("identityToken", false, "Generate google ID token (default: false)")
	audience        = flag.String("audience", "", "Audience for the OIDC token")
	svcAccountEmail = flag.String("svcAccountEmail", "", "Service Account Email")

	// mtls Options
	useMTLS       = flag.Bool("useMTLS", false, "Use mtls workload federation(default: false)")
	projectNumber = flag.String("projectNumber", "", "Project Number for mTLS (default: )")
	poolID        = flag.String("poolID", "", "workload identity pool id for mTLS (default: )")
	providerID    = flag.String("providerID", "", "workload identity pool id for mTLS (default: )")
	pubCert       = flag.String("pubCert", "", "workload identity public certificate for mTLS (default: )")

	rawOutput = flag.Bool("rawOutput", false, "return just the token, nothing else")

	sessionEncryptionName = flag.String("tpm-session-encrypt-with-name", "", "hex encoded TPM object 'name' to use with an encrypted session")
	version               = flag.Bool("version", false, "print version")

	Commit, Tag, Date string
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
		// } else if path == "simulator" {
		// 	return simulator.Get()
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	flag.Parse()

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Printf("Version: %s\n", Tag)
		fmt.Printf("Date: %s\n", Date)
		fmt.Printf("Commit: %s\n", Commit)
		os.Exit(0)
	}

	parentPasswordAuth := getEnv(parent_pass_var, "", *parentPass)
	keyPasswordAuth := getEnv(key_pass_var, "", *keyPass)

	rwr, err := openTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gcp-tpm-process-credential: Error opening TPM %v", err)
		os.Exit(1)
	}

	var cert *x509.Certificate
	if *useMTLS {
		certPEMBlock, err := os.ReadFile(*pubCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gcp-tpm-process-credential:failed to read certificate file: %v", err)
		}

		// Decode the PEM block
		block, _ := pem.Decode(certPEMBlock)
		if block == nil || block.Type != "CERTIFICATE" {
			fmt.Fprintf(os.Stderr, "gcp-tpm-process-credential: failed to decode PEM block as certificate")
			os.Exit(1)
		}

		// Parse the X.509 certificate
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gcp-tpm-process-credential:  failed to parse certificate: %v", err)
			os.Exit(1)
		}
	}

	resp, err := gcptpmcredential.NewGCPTPMCredential(&gcptpmcredential.GCPTPMConfig{
		TPMCloser:        rwr,
		PersistentHandle: uint(*persistentHandle),
		CredentialFile:   *keyfilepath,

		IdentityToken:         *identityToken,
		Audience:              *audience,
		ServiceAccountEmail:   *svcAccountEmail,
		ExpireIn:              *expireIn,
		Scopes:                strings.Split(*scopes, ","),
		SessionEncryptionName: *sessionEncryptionName,
		Parentpass:            parentPasswordAuth,
		Keypass:               keyPasswordAuth,
		Pcrs:                  *pcrs,
		UseOauthToken:         *useOauthToken,
		UseEKParent:           *useEKParent,

		UseMTLS:       *useMTLS,
		ProjectNumber: *projectNumber,
		PoolID:        *poolID,
		ProviderID:    *providerID,
		Certificate:   cert,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "gcp-tpm-process-credential: Error getting credentials %v", err)
		os.Exit(1)
	}
	if *rawOutput {
		fmt.Println(resp.AccessToken)
		return
	}
	m, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gcp-tpm-process-credential: Error marshalling processCredential output %v", err)
		os.Exit(1)
	}
	fmt.Println(string(m))
}

func getEnv(key, fallback string, fromArg string) string {
	if fromArg != "" {
		return fromArg
	}
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
