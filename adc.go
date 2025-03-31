// Creates creates GCP access tokens where the service account key
// is saved on a Trusted Platform Module (TPM).
//
//	see https://github.com/salrashid123/gce_metadata_server
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
)

type rtokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

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

	sessionEncryptionName = flag.String("tpm-session-encrypt-with-name", "", "hex encoded TPM object 'name' to use with an encrypted session")

	/*
		Template for the H2 h-2 is described in pg 43 [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r2_10feb2021.pdf)

		for use with KeyFiles described in 	[ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)

		printf '\x00\x00' > unique.dat
		tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat
	*/

	ECCSRK_H2_Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}
)

type oauthJWT struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

const (
	PARENT_PASS_VAR = "TPM_PARENT_AUTH"
	KEY_PASS_VAR    = "TPM_KEY_AUTH"
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// ExpiresIn is the OAuth2 wire format "expires_in" field,
	// which specifies how many seconds later the token expires,
	// relative to an unknown time base approximately around "now".
	// It is the application's responsibility to populate
	// `Expiry` from `ExpiresIn` when required.
	ExpiresIn int64 `json:"expires_in,omitempty"`
}

func main() {

	flag.Parse()
	ctx := context.Background()

	if *expireIn > 3600 {
		fmt.Fprintf(os.Stderr, "Token expiry cannot exceed 3600s")
		os.Exit(1)
	}

	rwc, err := openTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't open TPM %s: %v", *tpmPath, err)
		os.Exit(1)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "can't close TPM %q: %v", *tpmPath, err)
			os.Exit(1)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	var encryptionSessionHandle tpm2.TPMHandle

	if *sessionEncryptionName != "" {

		createEKCmd := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
		}
		createEKRsp, err := createEKCmd.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't acquire acquire ek %v", err)
			os.Exit(1)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: createEKRsp.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		encryptionSessionHandle = createEKRsp.ObjectHandle
		if *sessionEncryptionName != hex.EncodeToString(createEKRsp.Name.Buffer) {
			fmt.Fprintf(os.Stderr, "session encryption names do not match expected [%s] got [%s]", *sessionEncryptionName, hex.EncodeToString(createEKRsp.Name.Buffer))
			os.Exit(1)
		}
	}

	var svcAccountKey tpm2.TPMHandle

	parentPasswordAuth := getEnv(PARENT_PASS_VAR, "", *parentPass)
	keyPasswordAuth := getEnv(KEY_PASS_VAR, "", *keyPass)

	if *keyfilepath != "" {
		c, err := os.ReadFile(*keyfilepath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading private keyfile: %v", err)
			os.Exit(1)
		}
		key, err := keyfile.Decode(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, " failed decoding key: %v", err)
			os.Exit(1)
		}
		// specify its parent directly
		primaryKey, err := tpm2.CreatePrimary{
			PrimaryHandle: key.Parent,
			InPublic:      tpm2.New2B(ECCSRK_H2_Template),
		}.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't create primary %q: %v", *tpmPath, err)
			os.Exit(1)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		// now the actual key can get loaded from that parent
		svcAccountKeyResponse, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: primaryKey.ObjectHandle,
				Name:   tpm2.TPM2BName(primaryKey.Name),
				Auth:   tpm2.PasswordAuth([]byte(parentPasswordAuth)),
			},
			InPublic:  key.Pubkey,
			InPrivate: key.Privkey,
		}.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't load  rsaKey : %v", err)
			os.Exit(1)
		}
		svcAccountKey = svcAccountKeyResponse.ObjectHandle
	} else {
		svcAccountKey = tpm2.TPMHandle(*persistentHandle)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: svcAccountKey,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	var se tpmjwt.Session

	if *pcrs != "" {
		strpcrs := strings.Split(*pcrs, ",")
		var pcrList = []uint{}

		for _, i := range strpcrs {
			j, err := strconv.Atoi(i)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR:  could convert pcr value: %v", err)
				os.Exit(1)
			}
			pcrList = append(pcrList, uint(j))
		}

		sel := []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
			},
		}
		se, err = tpmjwt.NewPCRSession(rwr, sel)

	} else if keyPasswordAuth != "" {
		se, err = tpmjwt.NewPasswordSession(rwr, []byte(keyPasswordAuth))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR:  could not initialize Key: %v", err)
		os.Exit(1)
	}

	// now we're ready to sign

	iat := time.Now()
	exp := iat.Add(time.Duration(*expireIn) * time.Second)

	claims := &oauthJWT{
		Scope: strings.Replace(*scopes, ",", " ", -1),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(exp),
			Issuer:    *svcAccountEmail,
			Subject:   *svcAccountEmail,
		},
	}

	tpmjwt.SigningMethodTPMRS256.Override()
	jwt.MarshalSingleStringAsArray = false
	token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

	config := &tpmjwt.TPMConfig{
		TPMDevice:        rwc,
		Handle:           svcAccountKey,
		AuthSession:      se,
		EncryptionHandle: encryptionSessionHandle,
	}

	keyctx, err := tpmjwt.NewTPMContext(ctx, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to initialize tpmJWT: %v", err)
		os.Exit(1)
	}

	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing %v", err)
		os.Exit(1)
	}

	f := &Token{AccessToken: tokenString, TokenType: "Bearer", ExpiresIn: int64(exp.Sub(iat).Seconds())}

	fs, err := json.Marshal(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating json sting %v", err)
		os.Exit(1)
	}
	fmt.Println(string(fs))
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

func getExpectedPCRDigest(thetpm transport.TPM, selection tpm2.TPMLPCRSelection, hashAlg tpm2.TPMAlgID) ([]byte, error) {
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: selection,
	}

	pcrReadRsp, err := pcrRead.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	var expectedVal []byte
	for _, digest := range pcrReadRsp.PCRValues.Digests {
		expectedVal = append(expectedVal, digest.Buffer...)
	}

	cryptoHashAlg, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}

	hash := cryptoHashAlg.New()
	hash.Write(expectedVal)
	return hash.Sum(nil), nil
}
