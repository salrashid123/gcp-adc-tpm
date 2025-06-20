package main

import (
	"encoding/json"
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
	tpmPath          = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81010002, "Handle value")
	keyfilepath      = flag.String("keyfilepath", "", "TPM Encrypted KeyFile")
	svcAccountEmail  = flag.String("svcAccountEmail", "", "Service Account Email")
	parentPass       = flag.String("parentPass", "", "Passphrase for the owner handle (will use TPM_PARENT_AUTH env var)")
	keyPass          = flag.String("keyPass", "", "Passphrase for the key handle (will use TPM_KEY_AUTH env var)")
	pcrs             = flag.String("pcrs", "", "PCR Bound value (increasing order, comma separated)")
	expireIn         = flag.Int("expireIn", 3600, "Token expires in seconds")
	scopes           = flag.String("scopes", "https://www.googleapis.com/auth/cloud-platform", "comma separated scopes")

	identityToken = flag.Bool("identityToken", false, "Generate google ID token (default: false)")
	audience      = flag.String("audience", "", "Audience for the OIDC token")

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
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Error opening TPM %v", err)
		os.Exit(1)
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
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Error getting credentials %v", err)
		os.Exit(1)
	}
	m, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-tpm-process-credential: Error marshalling processCredential output %v", err)
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
