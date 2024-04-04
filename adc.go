package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
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
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")
	svcAccountEmail  = flag.String("svcAccountEmail", "", "Service Account Email")
)

type oauthJWT struct {
	jwt.RegisteredClaims
	Scope string `json:"scope"`
}

const ()

func main() {

	flag.Parse()
	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("can't open TPM %s: %v", *tpmPath, err)
		os.Exit(1)
	}
	defer rwc.Close()
	k, err := client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), nil)
	if err != nil {
		fmt.Printf("ERROR:  could not initialize Key: %v", err)
		os.Exit(1)
	}
	defer k.Close()
	// now we're ready to sign

	iat := time.Now()
	exp := iat.Add(time.Hour)

	claims := &oauthJWT{
		jwt.RegisteredClaims{
			Issuer:    *svcAccountEmail,
			Audience:  []string{"https://oauth2.googleapis.com/token"},
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		"https://www.googleapis.com/auth/cloud-platform",
	}

	tpmjwt.SigningMethodTPMRS256.Override()
	jwt.MarshalSingleStringAsArray = false
	token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

	ctx := context.Background()
	config := &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		Key:       k,
	}

	keyctx, err := tpmjwt.NewTPMContext(ctx, config)
	if err != nil {
		fmt.Printf("Unable to initialize tpmJWT: %v", err)
		os.Exit(1)
	}

	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		fmt.Printf("Error signing %v", err)
		os.Exit(1)
	}

	client := &http.Client{}

	data := url.Values{}
	data.Set("grant_type", "assertion")
	data.Add("assertion_type", "http://oauth.net/grant_type/jwt/1.0/bearer")
	data.Add("assertion", tokenString)

	hreq, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", bytes.NewBufferString(data.Encode()))
	if err != nil {
		fmt.Printf("Error: Unable to generate token Request, %v\n", err)
		os.Exit(1)
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	resp, err := client.Do(hreq)
	if err != nil {
		fmt.Printf("Error: unable to POST token request, %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: Token Request error:, %v\n", err)
		f, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error Reading response body, %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Error response from oauth2 %s\n", f)
		os.Exit(1)
	}

	f, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: unable to parse token response, %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	fmt.Println(string(f))
}
