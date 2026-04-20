package gcptpmcredential

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/stretchr/testify/require"
)

const (
	swTPMPath  = "127.0.0.1:2321"
	svcEnvVar  = "CICD_SA_PEM"
	mtlsEnvVar = "CICD_MTLS_KEY_PEM"
)

func loadH2Key(rwr transport.TPM, persistentHandle uint, keyFilePath string, envVarName string, rsaScheme tpm2.TPMAlgID) (tpm2.TPMHandle, tpm2.TPM2BName, func(), error) {

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

	saPEM := os.Getenv(envVarName)

	block, _ := pem.Decode([]byte(saPEM))
	if block == nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	pvk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	var sch tpm2.TPMTRSAScheme

	if rsaScheme == tpm2.TPMAlgRSAPSS {
		sch = tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgRSAPSS,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgRSAPSS,
				&tpm2.TPMSSigSchemeRSAPSS{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		}
	} else {
		sch = tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSigSchemeRSASSA{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		}
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
				Scheme:   sch,
				KeyBits:  2048,
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

func loadEKKey(rwr transport.TPM, parent tpm2.TPMTPublic, persistentHandle uint, keyFilePath string, envVarName string, rsaScheme tpm2.TPMAlgID) (tpm2.TPMHandle, tpm2.TPM2BName, func(), error) {

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(parent),
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

	saPEM := os.Getenv(envVarName)

	block, _ := pem.Decode([]byte(saPEM))
	if block == nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	pvk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	var sch tpm2.TPMTRSAScheme

	if rsaScheme == tpm2.TPMAlgRSAPSS {
		sch = tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgRSAPSS,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgRSAPSS,
				&tpm2.TPMSSigSchemeRSAPSS{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		}
	} else {
		sch = tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSigSchemeRSASSA{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		}
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
				Scheme:   sch,
				KeyBits:  2048,
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

	importSession, import_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	defer import_session_cleanup()

	_, err = tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth(nil),
		},
		PolicySession: importSession.Handle(),
		NonceTPM:      importSession.NonceTPM(),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   importSession,
		},
		ObjectPublic: tpm2.New2B(rsaTemplate),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	import_session_cleanup()

	importSession2, import_session_cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	defer import_session_cleanup2()

	_, err = tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth(nil),
		},
		PolicySession: importSession2.Handle(),
		NonceTPM:      importSession2.NonceTPM(),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	loadResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   importSession2,
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
		Parent:    tpm2.TPMRHEndorsement,
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
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008001
	_, _, closer, err := loadH2Key(rwr, uint(persistentHandle), filePath, svcEnvVar, tpm2.TPMAlgRSASSA)
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
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008002
	_, _, closer, err := loadH2Key(rwr, uint(persistentHandle), filePath, svcEnvVar, tpm2.TPMAlgRSASSA)
	require.NoError(t, err)
	closer()

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
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008003
	_, _, closer, err := loadH2Key(rwr, uint(persistentHandle), filePath, svcEnvVar, tpm2.TPMAlgRSASSA)
	require.NoError(t, err)
	closer()

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
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008004
	_, _, closer, err := loadH2Key(rwr, uint(persistentHandle), filePath, svcEnvVar, tpm2.TPMAlgRSASSA)
	require.NoError(t, err)
	closer()

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

func TestMTLSAccessToken(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008005
	_, _, closer, err := loadH2Key(rwr, uint(persistentHandle), filePath, mtlsEnvVar, tpm2.TPMAlgRSAPSS)
	require.NoError(t, err)
	closer()

	certPEMBlock := os.Getenv("CICD_MTLS_CERT_PEM")

	block, _ := pem.Decode([]byte(certPEMBlock))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	//saEmail := os.Getenv("CICD_SA_EMAIL")

	projectNumber := os.Getenv("CICD_PROJECT_NUMBER")
	poolID := os.Getenv("CICD_POOL_ID")
	providerID := os.Getenv("CICD_PROVIDER_ID")

	_, err = NewGCPTPMCredential(&GCPTPMConfig{
		TPMCloser:      tpmDevice,
		CredentialFile: filePath,
		//ServiceAccountEmail: saEmail,
		ExpireIn: 10,
		Scopes:   []string{"https://www.googleapis.com/auth/cloud-platform"},

		UseMTLS:       true,
		ProjectNumber: projectNumber,
		PoolID:        poolID,
		ProviderID:    providerID,
		Certificate:   cert,
	})
	require.NoError(t, err)

	//t.Log(resp.AccessToken)
}

func TestMTLSIDToken(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008006
	_, _, closer, err := loadH2Key(rwr, uint(persistentHandle), filePath, mtlsEnvVar, tpm2.TPMAlgRSAPSS)
	require.NoError(t, err)
	closer()

	certPEMBlock := os.Getenv("CICD_MTLS_CERT_PEM")

	block, _ := pem.Decode([]byte(certPEMBlock))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	saEmail := os.Getenv("CICD_SA_EMAIL")

	projectNumber := os.Getenv("CICD_PROJECT_NUMBER")
	poolID := os.Getenv("CICD_POOL_ID")
	providerID := os.Getenv("CICD_PROVIDER_ID")

	_, err = NewGCPTPMCredential(&GCPTPMConfig{
		TPMCloser:           tpmDevice,
		CredentialFile:      filePath,
		ServiceAccountEmail: saEmail,
		ExpireIn:            10,
		Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},

		UseMTLS:       true,
		IdentityToken: true,
		Audience:      "https://foo",
		ProjectNumber: projectNumber,
		PoolID:        poolID,
		ProviderID:    providerID,
		Certificate:   cert,
	})
	require.NoError(t, err)

	//t.Log(resp.AccessToken)
}

func TestKeyFileEKRSACredentials(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008007
	_, _, closer, err := loadEKKey(rwr, tpm2.RSAEKTemplate, uint(persistentHandle), filePath, svcEnvVar, tpm2.TPMAlgRSASSA)
	require.NoError(t, err)
	closer()

	saEmail := os.Getenv("CICD_SA_EMAIL")

	_, err = NewGCPTPMCredential(&GCPTPMConfig{
		TPMCloser:           tpmDevice,
		CredentialFile:      filePath,
		ServiceAccountEmail: saEmail,
		UseEKParent:         RSA_EK,
		ExpireIn:            10,
		Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},
	})
	require.NoError(t, err)
}

func TestKeyFileEKECCCredentials(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008008
	_, _, closer, err := loadEKKey(rwr, tpm2.ECCEKTemplate, uint(persistentHandle), filePath, svcEnvVar, tpm2.TPMAlgRSASSA)
	require.NoError(t, err)
	closer()

	saEmail := os.Getenv("CICD_SA_EMAIL")

	_, err = NewGCPTPMCredential(&GCPTPMConfig{
		TPMCloser:           tpmDevice,
		CredentialFile:      filePath,
		ServiceAccountEmail: saEmail,
		UseEKParent:         ECC_EK,
		ExpireIn:            10,
		Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},
	})
	require.NoError(t, err)
}
