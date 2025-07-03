package gcptpmcredential

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/stretchr/testify/require"
)

var ()

func loadKey(rwr transport.TPM, persistentHandle uint, keyFilePath string) (tpm2.TPMHandle, tpm2.TPM2BName, func(), error) {

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	saPEM := os.Getenv("CICD_SA_PEM")

	block, _ := pem.Decode([]byte(saPEM))
	if block == nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	pvk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	pv := pvk.(*rsa.PrivateKey)

	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Exponent: uint32(pv.PublicKey.E),
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),

		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pv.PublicKey.N.Bytes(),
			},
		),
	}

	sens2B := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgRSA,
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPrivateKeyRSA{Buffer: pv.Primes[0].Bytes()},
		),
	})

	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectPublic: tpm2.New2B(rsaTemplate),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	loadResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  tpm2.New2B(rsaTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: loadResponse.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	closer := func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: loadResponse.ObjectHandle,
			Name:   pub.Name,
		},
		PersistentHandle: tpm2.TPMHandle(persistentHandle),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	tkf := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		EmptyAuth: true,
		Parent:    tpm2.TPMRHOwner,
		Pubkey:    tpm2.New2B(rsaTemplate),
		Privkey:   importResponse.OutPrivate,
	}
	b := new(bytes.Buffer)
	err = keyfile.Encode(b, tkf)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	err = os.WriteFile(keyFilePath, b.Bytes(), 0644)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	return loadResponse.ObjectHandle, pub.Name, closer, nil
}

func TestPersistentHandleCredentials(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008001
	_, _, closer, err := loadKey(rwr, uint(persistentHandle), filePath)
	require.NoError(t, err)
	defer closer()

	saEmail := os.Getenv("CICD_SA_EMAIL")

	_, err = NewGCPTPMCredential(&GCPTPMConfig{
		TPMCloser:           tpmDevice,
		PersistentHandle:    uint(persistentHandle),
		ServiceAccountEmail: saEmail,
		ExpireIn:            10,
		Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},
	})
	require.NoError(t, err)

	//t.Log(resp.AccessToken)

}

func TestKeyFileCredentials(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008001
	_, _, closer, err := loadKey(rwr, uint(persistentHandle), filePath)
	require.NoError(t, err)
	defer closer()

	saEmail := os.Getenv("CICD_SA_EMAIL")

	_, err = NewGCPTPMCredential(&GCPTPMConfig{
		TPMCloser:           tpmDevice,
		CredentialFile:      filePath,
		ServiceAccountEmail: saEmail,
		ExpireIn:            10,
		Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},
	})
	require.NoError(t, err)

	//t.Log(resp.AccessToken)
}

func TestOauth2Token(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008001
	_, _, closer, err := loadKey(rwr, uint(persistentHandle), filePath)
	require.NoError(t, err)
	defer closer()

	saEmail := os.Getenv("CICD_SA_EMAIL")

	_, err = NewGCPTPMCredential(&GCPTPMConfig{
		TPMCloser:           tpmDevice,
		CredentialFile:      filePath,
		ServiceAccountEmail: saEmail,
		ExpireIn:            10,
		UseOauthToken:       true,
		Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},
	})
	require.NoError(t, err)

	//t.Log(resp.AccessToken)
}

func TestIdToken(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008001
	_, _, closer, err := loadKey(rwr, uint(persistentHandle), filePath)
	require.NoError(t, err)
	defer closer()

	saEmail := os.Getenv("CICD_SA_EMAIL")

	_, err = NewGCPTPMCredential(&GCPTPMConfig{
		TPMCloser:           tpmDevice,
		CredentialFile:      filePath,
		ServiceAccountEmail: saEmail,
		ExpireIn:            10,
		IdentityToken:       true,
		Audience:            "https://foo.bar",
		Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},
	})
	require.NoError(t, err)

	//t.Log(resp.AccessToken)
}
