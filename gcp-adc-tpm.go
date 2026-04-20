// Creates creates GCP access tokens where the service account key
// is saved on a Trusted Platform Module (TPM).

package gcptpmcredential

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	jwt "github.com/golang-jwt/jwt/v5"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
	"golang.org/x/oauth2"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	credentialspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpmmtls "github.com/salrashid123/mtls-tokensource/tpm"
	"google.golang.org/api/option"
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
	TPMCloser        io.ReadWriteCloser // TPM Reqd closer
	PersistentHandle uint               // use if key is referenced as persistent handle
	CredentialFile   string             // use if key is referenced as PEM keyfile

	ExpireIn int // how long the JWTAccessToken is valid for

	IdentityToken         bool          // return an id token
	UseEKParent           ParentKeyType // set true if the parent is rsa_ek or ecc_ek
	Audience              string        // audience for the id_token
	ServiceAccountEmail   string        // name of the service account
	Scopes                []string      // scopes to provide
	SessionEncryptionName string        // hex string "name" of the rsa_ek to use for session encryption
	Parentpass            string        // password for the parent object
	Keypass               string        // password for the key object
	Pcrs                  string        // string form of the pcrs to use (formatted as pcr_bank:pcr_sha256Hex)
	UseOauthToken         bool          // enables oauth2 token (default: false)

	UseMTLS       bool              // enables mtls workload federation
	ProjectNumber string            //used for mtls workload federation
	PoolID        string            //used for mtls workload federation
	ProviderID    string            //used for mtls workload federation
	Certificate   *x509.Certificate //used for mtls workload federation
}

var ()

type ParentKeyType int

const (
	H2 ParentKeyType = iota
	RSA_EK
	ECC_EK
)

func (d ParentKeyType) String() string {
	return [...]string{"h2", "rsa_ek", "ecc_ek"}[d]
}

func NewGCPTPMCredential(cfg *GCPTPMConfig) (t Token, e error) {

	rwr := transport.FromReadWriter(cfg.TPMCloser)

	// first acquire the default RSA EK key to use for encrypted sessions.  You should
	// supply the SessionEncryptionName parameter (othewise getting the default rsa_ek manually isn't too secure anwyay...)
	var encryptionSessionHandle tpm2.TPMHandle
	createEKRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth([]byte(cfg.Parentpass)),
		},
		InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
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

	ekoutPub, err := createEKRsp.OutPublic.Contents()
	if err != nil {
		return Token{}, fmt.Errorf("gcp-adc-tpm: error getting encryption name %v", err)
	}

	// if the encryptionName was specified as argument, compare it
	if cfg.SessionEncryptionName != "" {
		if cfg.SessionEncryptionName != hex.EncodeToString(createEKRsp.Name.Buffer) {
			return Token{}, fmt.Errorf("gcp-adc-tpm: session encryption names do not match expected [%s] got [%s]", cfg.SessionEncryptionName, hex.EncodeToString(createEKRsp.Name.Buffer))
		}
	}

	// this is the service account key to use for getting a token
	var svcAccountKey tpm2.TPMHandle

	parentPasswordAuth := getEnv(PARENT_PASS_VAR, "", cfg.Parentpass)
	keyPasswordAuth := getEnv(KEY_PASS_VAR, "", cfg.Keypass)

	var primaryKey *tpm2.CreatePrimaryResponse
	var parentSession tpm2.Session

	// if a keyfile was specfified
	if cfg.CredentialFile != "" {
		c, err := os.ReadFile(cfg.CredentialFile)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: error reading private keyfile: %v", err)
		}
		key, err := keyfile.Decode(c)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: failed decoding key: %v", err)
		}

		// are we deailing with an rsa_ek or ecc_ek, if so, we need to create the appropriate parent
		if cfg.UseEKParent == RSA_EK || cfg.UseEKParent == ECC_EK {
			var keytype tpm2.TPMTPublic
			switch cfg.UseEKParent {
			case RSA_EK:
				keytype = tpm2.RSAEKTemplate
			case ECC_EK:
				keytype = tpm2.ECCEKTemplate
			default:
				return Token{}, fmt.Errorf("gcp-adc-tpm: unsupported ekparent: %s", cfg.UseEKParent)
			}
			// create the parent
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth([]byte(cfg.Parentpass)),
				},
				InPublic: tpm2.New2B(keytype),
			}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: can't create pimaryEK: %v", err)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			// load it
			var load_session_cleanup func() error
			parentSession, load_session_cleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: can't load policysession : %v", err)
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
			}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: can't create policysecret: %v", err)
			}

		} else {

			// were' dealing with the default "H2" parent
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: key.Parent,
				InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
			}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: can't create primary (primary maybe RSAEK, not H2, try --useEKParent):   %v", err)
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
		}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm:can't load  rsaKey : %v", err)
		}
		svcAccountKey = svcAccountKeyResponse.ObjectHandle
	} else {

		//  we deailing with a persistent handle

		// first load the parent if rsa_ek or ecc_ek
		if cfg.UseEKParent != H2 {
			var keytype tpm2.TPMTPublic
			switch cfg.UseEKParent {
			case RSA_EK:
				keytype = tpm2.RSAEKTemplate
			case ECC_EK:
				keytype = tpm2.ECCEKTemplate
			default:
				return Token{}, fmt.Errorf("gcp-adc-tpm: unsupported ekparent: %s", cfg.UseEKParent)
			}
			var err error
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: tpm2.AuthHandle{
					Handle: primaryKey.ObjectHandle,
					Name:   tpm2.TPM2BName(primaryKey.Name),
					Auth:   parentSession,
				},
				InPublic: tpm2.New2B(keytype),
			}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: can't create pimaryEK: %v", err)
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
				return Token{}, fmt.Errorf("gcp-adc-tpm: can't load policysession : %v", err)
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
			}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: can't create policysecret: %v", err)
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

	// now initialize a session.  if pcrs are set, construct the TPMPCRSelections to validate against
	var se tpmjwt.Session
	if cfg.Pcrs != "" {

		pcrMap := make(map[uint][]byte)
		for _, v := range strings.Split(cfg.Pcrs, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					return Token{}, fmt.Errorf("gcp-adc-tpm:  could parse pcr values: %v", err)
				}
				hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
				if err != nil {
					return Token{}, fmt.Errorf("gcp-adc-tpm:  could parse pcr values: %v", err)
				}
				pcrMap[uint(uv)] = hexEncodedPCR
			}
		}
		_, pcrList, pcrHash, err := getPCRMap(tpm2.TPMAlgSHA256, pcrMap)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm:  could get pcrMap: %v", err)
		}

		sel := []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
			},
		}

		// if the parent was not h2, we're assuming it was duplicated using
		//  tpmcopy utility.  In this case the key is always bond with s apsecific policy
		// see https://github.com/salrashid123/tpmcopy/tree/main#bound-key-policy
		if cfg.UseEKParent != H2 {
			// initialize a bound key policy to duplicate select + PCRs
			se, err = tpmjwt.NewPCRAndDuplicateSelectSession(rwr, sel, tpm2.TPM2BDigest{Buffer: pcrHash}, []byte(cfg.Keypass), primaryKey.Name, encryptionSessionHandle)
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: can't create authsession: %v", err)
			}
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
		} else {

			// if its h2, just iniialzie a regular PCR session
			se, err = tpmjwt.NewPCRSession(rwr, sel, tpm2.TPM2BDigest{Buffer: pcrHash}, encryptionSessionHandle)
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm:  could get NewPCRSession: %v", err)
			}
		}

	} else if keyPasswordAuth != "" {

		if cfg.UseEKParent != H2 {
			se, err = tpmjwt.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(cfg.Keypass), primaryKey.Name, encryptionSessionHandle)
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: can't create authSession: %v", err)
			}
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
		} else {
			se, err = tpmjwt.NewPasswordAuthSession(rwr, []byte(keyPasswordAuth), encryptionSessionHandle)
		}
	}

	if err != nil {
		return Token{}, fmt.Errorf("gcp-adc-tpm:  could not initialize Key: %v", err)
	}

	// if w'ere using mTLS worload federation

	if cfg.UseMTLS {
		ctx := context.Background()

		if cfg.ProjectNumber == "" || cfg.PoolID == "" || cfg.ProviderID == "" {
			return Token{}, fmt.Errorf("gcp-adc-tpm: both ProjectNumber, ProviderID PoolID must be specified for mtls")
		}

		// supply the key, certificate and pool to get an token handle
		ts, err := tpmmtls.TpmMTLSTokenSource(&tpmmtls.TpmMtlsTokenConfig{
			TPMDevice:        cfg.TPMCloser,
			Handle:           svcAccountKey,
			Audience:         fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", cfg.ProjectNumber, cfg.PoolID, cfg.ProviderID),
			X509Certificate:  cfg.Certificate,
			EncryptionHandle: createEKRsp.ObjectHandle,
		})
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: error getting token %v", err)
		}

		// use the token handle to get a credential client
		c, err := credentials.NewIamCredentialsClient(ctx, option.WithTokenSource(ts))
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-tpm: error  creatubg IAM Client: %v", err)
		}
		defer c.Close()

		// if w'ere asking for an id_token and mTLS worload federation, use the IAM API
		if cfg.IdentityToken {

			if cfg.ServiceAccountEmail == "" || cfg.Audience == "" {
				return Token{}, fmt.Errorf("gcp-adc-tpm: both serviceAccountEmail and Audience must be specified for id_tokens")
			}

			idreq := &credentialspb.GenerateIdTokenRequest{
				Name:         fmt.Sprintf("projects/-/serviceAccounts/%s", cfg.ServiceAccountEmail),
				Audience:     cfg.Audience,
				IncludeEmail: true,
			}
			idresp, err := c.GenerateIdToken(ctx, idreq)
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: error  getting id_token: %v", err)
			}
			secondsDiff := 3600

			// were done, return the id_token
			return Token{
				AccessToken: idresp.Token,
				ExpiresIn:   int64(secondsDiff),
				TokenType:   "Bearer",
			}, nil
		} else {

			// otherwise get an access_token
			if cfg.ServiceAccountEmail != "" {

				ctx := context.Background()

				atreq := &credentialspb.GenerateAccessTokenRequest{
					Name:  fmt.Sprintf("projects/-/serviceAccounts/%s", cfg.ServiceAccountEmail),
					Scope: cfg.Scopes,
				}
				atresp, err := c.GenerateAccessToken(ctx, atreq)
				if err != nil {
					return Token{}, fmt.Errorf("gcp-adc-tpm: error  getting access_token: %v", err)
				}
				secondsDiff := 3600

				return Token{
					AccessToken: atresp.AccessToken,
					ExpiresIn:   int64(secondsDiff),
					TokenType:   "Bearer",
				}, nil

			}

			tok, err := ts.Token()
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-tpm: error getting token %v", err)
			}

			secondsDiff := int(time.Until(tok.Expiry).Seconds())
			// we're done, return the access token
			return Token{
				AccessToken: tok.AccessToken,
				ExpiresIn:   int64(secondsDiff),
				TokenType:   tok.TokenType,
			}, nil
		}
	}

	// now back to the point where we're not using mTLS but we need an id+token
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

		// use the service account to sign a JWT
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

		// now exchange the JWT for an id_token with google's endpoint
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

		// now return the id_token
		f := Token{AccessToken: t.AccessToken, TokenType: "Bearer", ExpiresIn: int64(defaultExpSeconds)}

		return f, nil

	}

	var f Token
	ctx := context.Background()

	// we need either an access token without mTLS
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

	// if we need a full oauth token, then we need to sign a jwt and exhange it with google
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
			return Token{}, fmt.Errorf("gcp-adc-tpm: Token Request error:, %s", string(f))
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

		// otherwise, just sign a JWT and return it (i.,e JWT AccessToken)
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

func getPCRMap(algo tpm2.TPMAlgID, pcrMap map[uint][]byte) (map[uint][]byte, []uint, []byte, error) {

	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm2.TPMAlgSHA1 {
		hsh = sha1.New()
	}
	if algo == tpm2.TPMAlgSHA256 {
		hsh = sha256.New()
	}

	if algo == tpm2.TPMAlgSHA1 || algo == tpm2.TPMAlgSHA256 {
		for uv, v := range pcrMap {
			pcrMap[uint(uv)] = v
			hsh.Write(v)
		}
	} else {
		return nil, nil, nil, fmt.Errorf("gcp-adc-tpm: unknown Hash Algorithm for TPM PCRs %v", algo)
	}

	pcrs := make([]uint, 0, len(pcrMap))
	for k := range pcrMap {
		pcrs = append(pcrs, k)
	}

	return pcrMap, pcrs, hsh.Sum(nil), nil
}
