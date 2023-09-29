package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/oauth2/jws"
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

const ()

func main() {

	flag.Parse()
	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("can't open TPM %s: %v", *tpmPath, err)
		os.Exit(1)
	}

	pHandle := tpmutil.Handle(uint32(*persistentHandle))

	// now we're ready to sign

	iat := time.Now()
	exp := iat.Add(time.Hour)

	hdr, err := json.Marshal(&jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
	})
	if err != nil {
		fmt.Printf("google: Unable to marshal  JWT Header: %v", err)
		os.Exit(1)
	}
	cs, err := json.Marshal(&jws.ClaimSet{
		Iss:   *svcAccountEmail,
		Scope: "https://www.googleapis.com/auth/cloud-platform",
		Aud:   "https://accounts.google.com/o/oauth2/token",
		Iat:   iat.Unix(),
		Exp:   exp.Unix(),
	})
	if err != nil {
		fmt.Printf("google: Unable to marshal  JWT ClaimSet: %v\n", err)
		os.Exit(1)
	}

	j := base64.URLEncoding.EncodeToString([]byte(hdr)) + "." + base64.URLEncoding.EncodeToString([]byte(cs))

	// now sign the data

	digest, hashValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, []byte(j), tpm2.HandleOwner)
	if err != nil {
		fmt.Printf("can't hash usign tpm %s: %v\n", *tpmPath, err)
		os.Exit(1)
	}

	sig, err := tpm2.Sign(rwc, pHandle, "", digest[:], hashValidation, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		fmt.Printf("Error Signing %s: %v\n", *tpmPath, err)
		os.Exit(1)
	}
	r := j + "." + base64.RawURLEncoding.EncodeToString([]byte(sig.RSA.Signature))

	client := &http.Client{}

	data := url.Values{}
	data.Set("grant_type", "assertion")
	data.Add("assertion_type", "http://oauth.net/grant_type/jwt/1.0/bearer")
	data.Add("assertion", r)

	hreq, err := http.NewRequest("POST", "https://accounts.google.com/o/oauth2/token", bytes.NewBufferString(data.Encode()))
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	if err != nil {
		fmt.Printf("Error: Unable to generate token Request, %v\n", err)
		os.Exit(1)
	}
	resp, err := client.Do(hreq)
	if err != nil {
		fmt.Printf("Error: unable to POST token request, %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("salrashid123/x/oauth2/google: Token Request error:, %v\n", err)
		f, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error Reading response body, %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Error response from oauth2 %s\n", f)
		os.Exit(1)
	}

	f, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: unable to parse token response, %v\n", err)
		os.Exit(1)
	}
	resp.Body.Close()
	// var m rtokenJSON
	// err = json.Unmarshal(f, &m)
	// if err != nil {
	// 	fmt.Printf("Error: Unable to unmarshal response, %v", err)
	// 	os.Exit(0)
	// }

	// b, err := json.Marshal(user)
	// if err != nil {
	//     fmt.Println(err)
	//     return
	// }
	fmt.Println(string(f))

}
