### TPM Credential Source for Google Cloud SDK

Binary that just returns a Service Accounts `access_token` for use with GCP Credential Libraries where the key is accessed using direct calls to a `Trusted Platform Module` (TPM).

While not running on a GCP platform like GCE, Cloud Run, GCF or GKE, `Service Account` authentication usually (with exception of workload federation) requires direct access to its RSA Private key.. 

You can see why here in the protocol itself: [Using OAuth 2.0 for Server to Server Applications](https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests).  Basically service account authentication involves locally signing a JWT using a registered private key and then exchanging the JWT for an `access_token`.

What this repo offers is a way to generate the JWT while the RSA key is embedded on a TPM and then use it to issue GCP `access_tokens`

(you can also import an external RSA to a device to the same effect but its more secure to have an unexportable key that'll never leave hardware).

The setup below shows how to use RSA keys on the device  to mint an x509 using `openssl` and then [upload that key to GCP](https://cloud.google.com/iam/docs/keys-upload#uploading) for binding to a service account.  Note that GCP service accounts can have [at most 10 keys](https://cloud.google.com/iam/quotas) associated with it.  This repo uses up one of those slots.  Sometimes you can "import" an RSA into an HSM but thats not covered here.

I'm not going into the background of what [PKCS-11](https://en.wikipedia.org/wiki/PKCS_11) is but will state that its pretty particular in its setup.

For reference, some of the providers and enablement technology stack this repo covers

and other references/reps for TPMs

* [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)
* [GCP golang TPMTokenSource](https://github.com/salrashid123/oauth2/blob/master/README.md#usage-tpmtokensource)
* [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)
* [TPM Remote Attestation protocol using go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation)
* [Sealing RSA and Symmetric keys with GCP vTPMs](https://github.com/salrashid123/gcp_tpm_sealed_keys)
* [golang-jwt for Trusted Platform Module (TPM)](https://github.com/salrashid123/golang-jwt-tpm)
* [TPM based TLS using Attested Keys](https://github.com/salrashid123/tls_ak)


Note, you can also embed AWS credentials to hardware:

* [AWS SDK Credentials and Request Signing using Trusted Platform Modules (TPM), HSM, PKCS-11 and Vault](https://github.com/salrashid123/aws_hmac)


>> NOTE: this repo is not supported by google

---

### Setup


On the TPM device, generate a self-signed  RSA key.

The following generates an RSA on the device, then a self-signed x509 cert.  It then creates a _persistent handle_ to the key on NV area of the TPM (so that it survives system reboots)

```bash
git clone https://github.com/salrashid123/go_tpm_https_embed.git
cd go_tpm_https_embed/
go run src/selfsigned/main.go 
more x509cert.pem 
```

Note that instead of a self-signed cert, the same repo above has a function that will issue a CSR which you can issue an x509 against.  

Also, if you're already using a persistent handle, you can pin another one using the args provided (or evict an existing one `tpm2_evictcontrol -c 0x81008000`)


Copy the cert over to any machine where you're logged into upload a svc account's key:


```bash
export PROJECT_ID=`gcloud config get-value core/project`

gcloud iam service-accounts create tpm-sa

gcloud iam service-accounts keys upload x509cert.pem  --iam-account tpm-sa@$PROJECT_ID.iam.gserviceaccount.com
gcloud iam service-accounts keys list --iam-account=tpm-sa@$PROJECT_ID.iam.gserviceaccount.com
```

At this point, the embedded RSA key on the TPM is authorized for access GCP.


On the machine with the TPM, specify the PROJECT_ID and the default persistent handle.  You should see an access token

```bash
CGO_ENABLED=0 go build -o gcp-adc-tpm adc.go

gcp-adc-tpm --persistentHandle=0x81008000 --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com"

## output is json Token specs
{
  "access_token": "ya29.c.c0AY_VpZjqp...redacted",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```



The json provided there can populate a generic [oauth2.Token](https://pkg.go.dev/golang.org/x/oauth2@v0.12.0#Token) which you can use in any GCP Library.

For example,

```golang
	sts := oauth2.StaticTokenSource(tok)
	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(sts))
```

You can also invoke this binary as a full TokenSource as well:  see

* `golang`: [https://github.com/salrashid123/gcp_process_credentials_go](https://github.com/salrashid123/gcp_process_credentials_go)
* `python`: [https://github.com/salrashid123/gcp_process_credentials_py](https://github.com/salrashid123/gcp_process_credentials_py)
* `java`: [https://github.com/salrashid123/gcp_process_credentials_java](https://github.com/salrashid123/gcp_process_credentials_java)
* `node`: [https://github.com/salrashid123/gcp_process_credentials_node](https://github.com/salrashid123/gcp_process_credentials_node)

for `gcloud` cli, you could apply the token directly using [--access-token-file](https://cloud.google.com/sdk/gcloud/reference#--access-token-file):

```bash
gcp-adc-tpm --persistentHandle=0x81008000 --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com" | jq -r '.access_token' > token.txt

gcloud storage ls --access-token-file=token.txt
``` 

---



Finally, you may want to restrict access to the TPM device by applying [tpm-udev.rules](https://github.com/salrashid123/tpm2#non-root-access-to-in-kernel-resource-manager-devtpmrm0-usint-tpm2-tss)


