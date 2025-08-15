// Creates creates GCP access tokens where the service account key
// is saved on a Trusted Platform Module (TPM).

package gcptpmcredential

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
)

type rtokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

var ()

type oauthJWT struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

const (
	PARENT_PASS_VAR = "TPM_PARENT_AUTH"
	KEY_PASS_VAR    = "TPM_KEY_AUTH"
)

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

type GCPTPMConfig struct {
	TPMCloser        io.ReadWriteCloser
	PersistentHandle uint
	CredentialFile   string

	ExpireIn int

	IdentityToken         bool
	UseEKParent           bool
	Audience              string
	ServiceAccountEmail   string
	Scopes                []string
	SessionEncryptionName string
	Parentpass            string
	Keypass               string
	Pcrs                  string
	UseOauthToken         bool // enables oauth2 token (default: false)
}

var ()

func NewGCPTPMCredential(cfg *GCPTPMConfig) (Token, error) {

	rwr := transport.FromReadWriter(cfg.TPMCloser)

	var encryptionSessionHandle tpm2.TPMHandle

	if cfg.SessionEncryptionName != "" {

		createEKCmd := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
		}
		createEKRsp, err := createEKCmd.Execute(rwr)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: can't acquire acquire ek %v", err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: createEKRsp.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		encryptionSessionHandle = createEKRsp.ObjectHandle
		if cfg.SessionEncryptionName != hex.EncodeToString(createEKRsp.Name.Buffer) {
			return Token{}, fmt.Errorf("gcp-adc-tpm: session encryption names do not match expected [%s] got [%s]", cfg.SessionEncryptionName, hex.EncodeToString(createEKRsp.Name.Buffer))
		}
	}

	var svcAccountKey tpm2.TPMHandle

	parentPasswordAuth := getEnv(PARENT_PASS_VAR, "", cfg.Parentpass)
	keyPasswordAuth := getEnv(KEY_PASS_VAR, "", cfg.Keypass)

	var primaryKey *tpm2.CreatePrimaryResponse
	var parentSession tpm2.Session

	if cfg.CredentialFile != "" {
		c, err := os.ReadFile(cfg.CredentialFile)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: error reading private keyfile: %v", err)
		}
		key, err := keyfile.Decode(c)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: failed decoding key: %v", err)
		}

		// specify its parent directly
		if cfg.UseEKParent {
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
			}.Execute(rwr)
			if err != nil {
				return Token{}, fmt.Errorf("can't create pimaryEK: %v", err)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()
			var load_session_cleanup func() error
			parentSession, load_session_cleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				return Token{}, fmt.Errorf("an't load policysession : %v", err)
			}
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth([]byte(cfg.Parentpass)),
				},
				PolicySession: parentSession.Handle(),
				NonceTPM:      parentSession.NonceTPM(),
			}.Execute(rwr)
			if err != nil {
				return Token{}, fmt.Errorf("can't create policysecret: %v", err)
			}

		} else {
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: key.Parent,
				InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
			}.Execute(rwr)
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: can't create primary  %v", err)
			}
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()
			parentSession = tpm2.PasswordAuth([]byte(parentPasswordAuth))
		}

		// now the actual key can get loaded from that parent
		svcAccountKeyResponse, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: primaryKey.ObjectHandle,
				Name:   tpm2.TPM2BName(primaryKey.Name),
				Auth:   parentSession,
			},
			InPublic:  key.Pubkey,
			InPrivate: key.Privkey,
		}.Execute(rwr)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm:can't load  rsaKey : %v", err)
		}
		svcAccountKey = svcAccountKeyResponse.ObjectHandle
	} else {
		if cfg.UseEKParent {
			var err error
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
			}.Execute(rwr)
			if err != nil {
				return Token{}, fmt.Errorf("can't create pimaryEK: %v", err)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()
			var load_session_cleanup func() error
			parentSession, load_session_cleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				return Token{}, fmt.Errorf("an't load policysession : %v", err)
			}
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth([]byte(cfg.Parentpass)),
				},
				PolicySession: parentSession.Handle(),
				NonceTPM:      parentSession.NonceTPM(),
			}.Execute(rwr)
			if err != nil {
				return Token{}, fmt.Errorf("can't create policysecret: %v", err)
			}

		}
		svcAccountKey = tpm2.TPMHandle(cfg.PersistentHandle)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: svcAccountKey,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	if encryptionSessionHandle != 0 {
		encryptionSessionHandle = primaryKey.ObjectHandle
	}

	var se tpmjwt.Session
	var err error
	if cfg.Pcrs != "" {
		strpcrs := strings.Split(cfg.Pcrs, ",")
		var pcrList = []uint{}

		for _, i := range strpcrs {
			j, err := strconv.Atoi(i)
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm:  could convert pcr value: %v", err)
			}
			pcrList = append(pcrList, uint(j))
		}

		sel := []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
			},
		}

		if cfg.UseEKParent {

			se, err = tpmjwt.NewPCRAndDuplicateSelectSession(rwr, sel, tpm2.TPM2BDigest{Buffer: nil}, []byte(cfg.Keypass), primaryKey.Name, encryptionSessionHandle)
			if err != nil {
				return Token{}, fmt.Errorf("can't create autsession: %v", err)
			}
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		} else {
			se, err = tpmjwt.NewPCRSession(rwr, sel, tpm2.TPM2BDigest{Buffer: nil}, primaryKey.ObjectHandle)
		}

	} else if keyPasswordAuth != "" {

		if cfg.UseEKParent {
			se, err = tpmjwt.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(cfg.Keypass), primaryKey.Name, encryptionSessionHandle)
			if err != nil {
				return Token{}, fmt.Errorf("can't create autsession: %v", err)
			}
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		} else {
			se, err = tpmjwt.NewPasswordSession(rwr, []byte(keyPasswordAuth), encryptionSessionHandle)
		}
	}

	if err != nil {
		return Token{}, fmt.Errorf("gcp-adc-tpm:  could not initialize Key: %v", err)
	}

	// now we're ready to sign

	if cfg.IdentityToken {
		if cfg.Audience == "" {
			return Token{}, fmt.Errorf("gcp-adc-tpm:  audience must be set if --identityToken is used")
		}
		iat := time.Now()
		exp := iat.Add(time.Second * time.Duration(cfg.ExpireIn))

		type idTokenJWT struct {
			jwt.RegisteredClaims
			TargetAudience string `json:"target_audience"`
		}

		claims := &idTokenJWT{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.ServiceAccountEmail,
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
				Audience:  []string{"https://oauth2.googleapis.com/token"},
			},
			TargetAudience: cfg.Audience,
		}

		tpmjwt.SigningMethodTPMRS256.Override()
		jwt.MarshalSingleStringAsArray = false
		token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

		ctx := context.Background()
		config := &tpmjwt.TPMConfig{
			TPMDevice:        cfg.TPMCloser,
			Handle:           svcAccountKey,
			AuthSession:      se,
			EncryptionHandle: encryptionSessionHandle,
		}
		keyctx, err := tpmjwt.NewTPMContext(ctx, config)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: Unable to initialize tpmJWT: %v", err)
		}

		tokenString, err := token.SignedString(keyctx)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: Error signing %v", err)
		}
		client := &http.Client{}

		data := url.Values{}
		data.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		data.Add("assertion", tokenString)

		hreq, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", bytes.NewBufferString(data.Encode()))
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: Error: Unable to generate token Request, %v", err)
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		resp, err := client.Do(hreq)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm:  unable to POST token request, %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			f, err := io.ReadAll(resp.Body)
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: Error Reading response body, %v", err)

			}
			return Token{}, fmt.Errorf("gcp-adc-tpm: Error: Token Request error:, %s", f)
		}
		defer resp.Body.Close()

		type idTokenResponse struct {
			IdToken string `json:"id_token"`
		}

		var ret idTokenResponse
		err = json.NewDecoder(resp.Body).Decode(&ret)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: Error: decoding token:, %s", err)

		}
		idTokenSource := oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: ret.IdToken,
		})
		t, err := idTokenSource.Token()
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: Error: decoding token:, %s", err)

		}
		defaultExpSeconds := 3600
		f := Token{AccessToken: t.AccessToken, TokenType: "Bearer", ExpiresIn: int64(defaultExpSeconds)}

		return f, nil

	}

	var f Token
	ctx := context.Background()

	config := &tpmjwt.TPMConfig{
		TPMDevice:        cfg.TPMCloser,
		Handle:           svcAccountKey,
		AuthSession:      se,
		EncryptionHandle: encryptionSessionHandle,
	}
	keyctx, err := tpmjwt.NewTPMContext(ctx, config)
	if err != nil {
		return Token{}, fmt.Errorf("gcp-adc-tpm: Error signing %v", err)
	}

	tpmjwt.SigningMethodTPMRS256.Override()
	jwt.MarshalSingleStringAsArray = false

	if cfg.UseOauthToken {

		iat := time.Now()
		exp := iat.Add(10 * time.Second) // we only need this JWT valid long enough to exchange for an access_token

		claims := &oauthJWT{
			Scope: strings.Join(cfg.Scopes, " "),
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
				Issuer:    cfg.ServiceAccountEmail,
				Audience:  []string{"https://oauth2.googleapis.com/token"},
			},
		}

		token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

		tokenString, err := token.SignedString(keyctx)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: Error signing %v", err)
		}
		client := &http.Client{}

		data := url.Values{}
		data.Set("grant_type", "assertion")
		data.Add("assertion_type", "http://oauth.net/grant_type/jwt/1.0/bearer")
		data.Add("assertion", tokenString)

		hreq, err := http.NewRequest(http.MethodPost, "https://accounts.google.com/o/oauth2/token", bytes.NewBufferString(data.Encode()))
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: Error signing %v", err)
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		resp, err := client.Do(hreq)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: Error signing %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			f, err := io.ReadAll(resp.Body)
			defer resp.Body.Close()
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: Error signing %v", err)
			}
			return Token{}, fmt.Errorf("salrashid123/x/oauth2/google: Token Request error:, %s", string(f))
		}

		fa, err := io.ReadAll(resp.Body)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: Error signing %v", err)
		}
		resp.Body.Close()
		var m rtokenJSON
		err = json.Unmarshal(fa, &m)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: Error signing %v", err)
		}
		defaultExpSeconds := 3600
		f = Token{AccessToken: m.AccessToken, TokenType: "Bearer", ExpiresIn: int64(defaultExpSeconds)}

	} else {

		iat := time.Now()
		exp := iat.Add(time.Duration(cfg.ExpireIn) * time.Second)

		claims := &oauthJWT{
			Scope: strings.Join(cfg.Scopes, " "),
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
				Issuer:    cfg.ServiceAccountEmail,
				Subject:   cfg.ServiceAccountEmail,
			},
		}

		token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

		tokenString, err := token.SignedString(keyctx)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: Error signing %v", err)
		}

		f = Token{AccessToken: tokenString, TokenType: "Bearer", ExpiresIn: int64(cfg.ExpireIn)}
	}

	return f, nil
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
