### TPM Credential Source for Google Cloud SDK

Binary that just returns a Service Accounts `access_token` for use with GCP Credential Libraries where the key is accessed using direct calls to a `Trusted Platform Module` (TPM).

While not running on a GCP platform like GCE, Cloud Run, GCF or GKE, `Service Account` authentication usually (with exception of workload federation) requires direct access to its RSA Private key.. 

You can see why here in the protocol itself in [AIP-4111: Self-signed JWT with Scopes](https://google.aip.dev/auth/4111).  Basically service account authentication involves locally signing a JWT and using that directly as an  `access_token`.

What this repo offers is a way to generate the JWT while the RSA key is embedded on a TPM and then use it to issue GCP `access_tokens`

This repo also allow you to embed an mTLS certificate into a TPM for use with [GCP Workload Federation with x509 certificates](https://cloud.google.com/iam/docs/workload-identity-federation-with-x509-certificates) where the private key is either

There are several ways to embed a GCP Service Account into a TPM.  

1. download a Google ServiceAccount's json file and embed the private part to the TPM or
2. Generate a Key ON THE TPM and then import the public part to GCP. or
3. remote seal the service accounts RSA Private key remotely, encrypt it with the remote TPM's Endorsement Key and load it

These are described here: [oauth2 TPM TokenSource](https://github.com/salrashid123/oauth2/blob/master/README.md#usage-tpmtokensource)

This specific demo here will use option (1) which is the easiest but ultimately, you just need a reference handle to the TPM which all three options can provide.

> *NOTE* While this repo is a CLI,  you can acquire an embedded service account's token for use with a library as an [oauth2 TPM TokenSource](https://github.com/salrashid123/oauth2/blob/master/README.md#usage-tpmtokensource)


for mTLS certificates, the you can

1. create a private key on the TPM and issue a CSR to sign by a CA 
2. create a private key, sign it by a CA and then embed the private key on the tpm

to use mTLS, you need to please see [GCP Workload Identity Federation using x509 certificates](https://github.com/salrashid123/mtls-tokensource)

---

### References

* [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)
* [GCP golang TPMTokenSource](https://github.com/salrashid123/oauth2/blob/master/README.md#usage-tpmtokensource)
* [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)
* [TPM Remote Attestation protocol using go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation)
* [Sealing RSA and Symmetric keys with GCP vTPMs](https://github.com/salrashid123/gcp_tpm_sealed_keys)
* [golang-jwt for Trusted Platform Module (TPM)](https://github.com/salrashid123/golang-jwt-tpm)
* [TPM based TLS using Attested Keys](https://github.com/salrashid123/tls_ak)

as an side, you can also embed AWS credentials to hardware:

* [AWS SDK Credentials and Request Signing using Trusted Platform Modules (TPM), HSM, PKCS-11 and Vault](https://github.com/salrashid123/aws_hmac)

---

>> NOTE: this repo is not supported by google

---

### Configuration Options

You can set the following options on usage:

#### Common Options
| Option | Description |
|:------------|-------------|
| **`--tpm-path`** | path to the TPM device (default: `/dev/tpm0`) |
| **`--persistentHandle`** | Persistent Handle for the HMAC key (default: `0x81010002`) |
| **`--keyfilepath`** | Path to the TPM HMAC credential file (default: ``) |
| **`--parentPass`** | Passphrase for the owner handle (will use TPM_PARENT_AUTH env var) |
| **`--keyPass`** | Passphrase for the key handle (will use TPM_KEY_AUTH env var) |
| **`--pcrs`** | "PCR Bound value (increasing order, comma separated)" |
| **`--rawOutput`** |  Return just the token, nothing else |
| **`--useEKParent`** | Use endorsement RSAKey as parent (default: false) |
| **`--tpm-session-encrypt-with-name`** | hex encoded TPM object 'name' to use with an encrypted session |

#### Oauth2 Options

| Option | Description |
| **`--useOauthToken`** | enable oauth2 token (default:false) |
| **`--svcAccountEmail`** | (required) Service Account Email |
| **`--identityToken`** |  Generate Google OIDC token |
| **`--audience`** |  Audience for the id_token |
| **`--scopes`** |  "comma separated scopes (default `https://www.googleapis.com/auth/cloud-platform`)" |
| **`--expireIn`** | "How many seconds the token is valid for" |


#### mTLS Options

| Option | Description |
| **`--useMTLS`** | Use mtls workload federation(default: false) |
| **`--projectNumber`** | Project Number for mTLS (default: ) |
| **`--poolID`** | workload identity pool id for mTLS (default: ) |
| **`--providerID`** | workload identity pool id for mTLS (default: ) |
| **`--pubCert`** | workload identity public certificate for mTLS (default: ) |


### Setup

since we're importing an external RSA key _into_ a TPM, we'll need a service account json file.

On your laptop, run

```bash
export PROJECT_ID=`gcloud config get-value core/project`
gcloud iam service-accounts create tpm-sa --display-name "TPM Service Account"
export SERVICE_ACCOUNT_EMAIL=tpm-sa@$PROJECT_ID.iam.gserviceaccount.com
gcloud iam service-accounts keys create tpm-svc-account.json --iam-account=$SERVICE_ACCOUNT_EMAIL
```

copy the `tpm-svc-account.json` to the system hosting the TPM.


On the TPM device, prepare the key and then use `tpm2_tools` to create a primary and import the service account into it.

```bash
## prepare they key
## extract just the private key from the json keyfile

cat tpm-svc-account.json | jq -r '.private_key' > /tmp/f.json
openssl rsa -in /tmp/f.json -out /tmp/key_rsa.pem 

## if you want to test using a software TPM instead:
##  rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
##  sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear
##  export TPM2TOOLS_TCTI="swtpm:port=2321"

## create the primary
### the specific primary here happens to be the h2 template described later on but you are free to define any template and policy

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

# import

tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256 -i /tmp/key_rsa.pem -u key.pub -r key.prv
tpm2_flushcontext  -t
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx 
tpm2_flushcontext  -t
```

Delete the svc account json and the extracted formats; theyr'e no longer needed 

You can either evict (save) the key to a `persistent_handle` or if you have [tpm2-tss-engine](https://github.com/tpm2-software/tpm2-tss-engine/blob/master/man/tpm2tss-genkey.1.md) installed, save the key to a PEM file

- `Evict`

```bash
## to load
tpm2_evictcontrol -C o -c key.ctx 0x81010002
```

note, Range for OWNER hierarchy is :`81 00 80 00 – 81 00 FF FF` from [Section 2.3.1 Key Handle Assignments of Registry of Reserved TPM 2.0: Handles and Localities](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf)

- `PEM`

```bash
tpm2_encodeobject -C primary.ctx -u key.pub -r key.prv -o private.pem
```

The TPM encrypted service account private key looks like:

```bash
-----BEGIN TSS2 PRIVATE KEY-----
MIICNQYGZ4EFCgEDoAMBAf8CBEAAAAEEggEaARgAAQALAAQAQAAAABAAFAALCAAA
AQABAQDqKVruwZ6amTB9OFXwOqNkl7Zaxh0jD1AXbnD9uvnk0z18tGOHxzsP6lsm
LJ8ywnMkomdbDP78dZlHEC3sn/7ustRUTwHb9UV/gc875gMJ0qsrbRajsH1J7tQB
S4ezEf8MKoBi9ogUx7g21z7cytiK46nr08J3yyZHvXVuCklncXBD8TM9ZlHVdDeM
ICMOzXg6d0fL0UvujGPSIEYnqbmY4DlpI0RudMAsOtActbo7Dq7xuiSBcW9slxxS
e18mO6/3IJANKVlHkynpjTEkzzchKR5brCoteukcLhSPTlSNmkvzBOXbDTyRhrrs
8HEyufQGc4MGLjStpTFNsOHy1xqnBIIBAAD+ACCa/b/fswSisyrTKwiDXPQh34iP
zBY1tFOd6vnC0/ve1wAQPG4ZuRWMOklDUbmDx4Lw8WG9dGQFNOFaQKCQhLUphFTs
bT12jDRmW87F7IPlJYbziyj6+4YVS0Ni1EoDJPlXpoveSE9AWONnqkqzTn9mlURI
ZGiTieMzKxfKxy7g/iwW8p0gkDuq/wR1zL6NScfD6HsEzGdpLHb3gVe8Y2VAwjb2
RLNfC7oAZv2rmq5OhKYTzcpCvO7rfL7X6lez4+ql9a04Jz3ui+QBGPSKO7KN0nir
qbW/+koHwS95LxjewjZ9aThg7tkaqAjlUqAZlayvvFDG1kjIhuDmN/0=
-----END TSS2 PRIVATE KEY-----
```

---

### Acquire access_token

At this point, the embedded RSA key on the TPM is authorized for access GCP.

On the machine with the TPM, specify the `PROJECT_ID` and the default persistent handle.  You should see an access token

You can either build the binary or acquire it from the `Releases` page

```bash
CGO_ENABLED=0 go build -o gcp-adc-tpm cmd/main.go

# with persistentHandle
./gcp-adc-tpm --persistentHandle=0x81010002 --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com"

# with keyfile
./gcp-adc-tpm --keyfilepath=/path/to/private.pem --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com"


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
gcp-adc-tpm --persistentHandle=0x81010002 --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com"  | jq -r '.access_token' > token.txt

gcloud storage ls --access-token-file=token.txt
``` 

### Acquire oauth2 token

The default token this utility returns is a `JWT AccessToken with Scopes` described in [AIP4111: Self-signed JWT](https://google.aip.dev/auth/4111).  This is a custom flow for Google Cloud APIs and is not an Oauth2 Token.

If you want to acquire an actual oauth2 token as described [here](https://developers.google.com/identity/protocols/oauth2#serviceaccount) request, then just set `--useOauthToken` flag

```bash
./gcp-adc-tpm --keyfilepath=/path/to/private.pem \
   --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com -useOauthToken 
```

### Acquire identity_token

This uitlity can also genrate [GCP OIDC TOken](https://github.com/salrashid123/google_id_token) using the TPM based key.

```bash
./gcp-adc-tpm   --keyfilepath=/path/to/private.pem  \
     --audience=foo --identityToken --serviceAccountEmail=tpm-sa@$PROJECT_ID.iam.gserviceaccount.com \
```

---

### PCR Policy

if you want to create a service account key which has a PCR policy attached to it:

```bash
tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_flushcontext session.dat

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256 -i /tmp/key_rsa.pem -u key.pub -r key.prv -L policy.dat
tpm2_flushcontext  -t
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx 

tpm2_evictcontrol -C o -c key.ctx 0x81010002
tpm2_flushcontext  -t
```

Then run it and specify the pcr back to construct the policy against:

```bash
./gcp-adc-tpm --persistentHandle=0x81010002  \
   --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com" --pcrs=23 
```

to test the negative, you can alter the PCR value.  For me it was

```bash
$ tpm2_pcrread sha256:23
  sha256:
    23: 0xC78009FDF07FC56A11F122370658A353AAA542ED63E44C4BC15FF4CD105AB33C

$ tpm2_pcrextend 23:sha256=0xC78009FDF07FC56A11F122370658A353AAA542ED63E44C4BC15FF4CD105AB33C
```

So now try to get an access token, you'll see an error:

```bash
./gcp-adc-tpm --persistentHandle=0x81010002  \
   --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com" --pcrs=23 

Error signing tpmjwt: can't Sign: TPM_RC_POLICY_FAIL (session 1): a policy check failedexit status 1
```

### Password Policy

if you want to create a service account key which has a Password policy attached to it:

```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_import -C primary.ctx -G rsa2048:rsassa:null  -p testpwd -g sha256 -i /tmp/key_rsa.pem -u key.pub -r key.prv 
tpm2_flushcontext  -t
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx 

tpm2_evictcontrol -C o -c key.ctx 0x81010002
tpm2_flushcontext  -t
```

Now run without the password, you'll see an error

```bash
./gcp-adc-tpm --persistentHandle=0x81010002  \
   --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com" 

Error signing tpmjwt: can't Sign: TPM_RC_AUTH_FAIL (session 1): the authorization HMAC check failed and DA counter incrementedexit status 1   
```

Now run  and specify the password

```bash
./gcp-adc-tpm --persistentHandle=0x81010002  \
   --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com"  --keyPass=testpwd
```

### gcloud CLI

If you want to use `gcloud` to authenticate using this provider:

with env-var:

```bash
$ export CLOUDSDK_AUTH_ACCESS_TOKEN=`/path/to/gcp-adc-tpm --keyfilepath path/to/tpm_private_key.pem  --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com"" | jq -r '.access_token'`

$ gcloud auth print-access-token
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY2....
```

or with file:  `--access-token-file`

```bash

echo /path/to/gcp-adc-tpm --keyfilepath path/to/tpm_private_key.pem  --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com"" | jq -r '.access_token' > /tmp/token.txt

gcloud auth print-access-token --access-token-file=/tmp/token.txt
```

Note that the token is static and non-refreshable through gcloud. Each token generated is new and has a TTL of 1hour.

Also note that issuing identity token is not supported

##### Use Endorsement Key as parent

If you used option `C` above to transfer the service account key from `TPM-A` to `TPM-B` (tpm-b being the system where you will run the metadata server):

you can use `tpm2_duplicate` or the  utility here [tpmcopy: Transfer RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)](https://github.com/salrashid123/tpmcopy) tool.  Note that the 'parent' key is set to `Endorsement RSA` which needs to get initialized on tpm-b first.  Furthermore, the key is bound by `pcr_duplicateselect` policy which must get fulfilled.

The following examples shows how to use this cli if you transferred the key using pcr or password policy as well as if you saved the transferred key as PEM or persistent handle

start two tpms to simulate two different system

```bash
## TPM A
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
/usr/share/swtpm/swtpm-create-user-config-files
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

## in new window
export TPM2TOOLS_TCTI="swtpm:port=2321"


## TPM B
rm -rf /tmp/myvtpm2 && mkdir /tmp/myvtpm2
/usr/share/swtpm/swtpm-create-user-config-files
swtpm_setup --tpmstate /tmp/myvtpm2 --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear --log level=2

## in new window
export TPM2TOOLS_TCTI="swtpm:port=2341"

tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l
```

* Password Policy

With service account key saved as PEM key file 

```bash
export TPMA="127.0.0.1:2321"
export TPMB="127.0.0.1:2341"

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2TOOLS_TCTI="swtpm:port=2341"

### TPM-B
tpmcopy --mode publickey --parentKeyType=rsa -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB
### copy public.pem to TPM-A

### TPM-A
tpmcopy --mode duplicate  --secret=/tmp/key_rsa.pem --keyType=rsa \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA

### copy out.json to TPM-B
### TPM-B
tpmcopy --mode import --parentKeyType=rsa --in=/tmp/out.json --out=/tmp/tpmkey.pem --parent=0x81008000 --tpm-path=$TPMB

### run 
go run cmd/main.go  --keyfilepath=/tmp/tpmkey.pem \
     --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com" \
     --useEKParent --keyPass=bar --tpm-path=127.0.0.1:2341
```

With service account key saved as a `PersistentHandle`

```bash
### TPM-B
tpmcopy --mode publickey --parentKeyType=rsa -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB
### copy public.pem to TPM-A

### TPM-A
tpmcopy --mode duplicate  --secret=/tmp/key_rsa.pem --keyType=rsa \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA

### copy out.json to TPM-B
### TPM-B
tpmcopy --mode import --parentKeyType=rsa \
 --in=/tmp/out.json --out=/tmp/tpmkey.pem \
 --pubout=/tmp/pub.dat --privout=/tmp/priv.dat \
  --parent=0x81008000 --tpm-path=$TPMB

tpmcopy --mode evict \
    --persistentHandle=0x81008001 \
   --in=/tmp/tpmkey.pem --tpm-path=$TPMB

# tpm2_createek -c ek.ctx -G rsa -u ek.pub 
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
# tpm2 startauthsession --session session.ctx --policy-session
# tpm2 policysecret --session session.ctx --object-context endorsement
# tpm2_load -C ek.ctx -c key.ctx -u pub.dat -r priv.dat --auth session:session.ctx
# tpm2_evictcontrol -c key.ctx 0x81008001
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

### run 
go run cmd/main.go  --keyfilepath=/tmp/tpmkey.pem \
     --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com" \
     --useEKParent --keyPass=bar --persistentHandle 0x81008001 --tpm-path=127.0.0.1:2341
```

* PCR Policy

Ensure `TPM-B` as a PCR you want to bind to

```bash
$ tpm2_pcrread sha256:23
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```

With service account key saved as PEM key file

```bash
### TPM-B
tpmcopy --mode publickey --parentKeyType=rsa -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB
### copy public.pem to TPM-A

### TPM-A
tpmcopy --mode duplicate --keyType=rsa    --secret=/tmp/key_rsa.pem \
     --pcrValues=23:f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b  \
      -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA
### copy out.json to TPM-B

### TPM-B
tpmcopy --mode import --parentKeyType=rsa --in=/tmp/out.json --out=/tmp/tpmkey.pem --tpm-path=$TPMB

### run 
go run cmd/main.go  --keyfilepath=/tmp/tpmkey.pem \
     --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com" \
     --useEKParent --pcrs=23 --tpm-path=127.0.0.1:2341
```

With service account key saved as a `PersistentHandle`

```bash
### TPM-B
tpmcopy --mode publickey --parentKeyType=rsa -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB
### copy public.pem to TPM-A

### TPM-A
tpmcopy --mode duplicate --keyType=rsa    --secret=/tmp/key_rsa.pem \
     --pcrValues=23:f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b  \
      -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA

### copy out.json to TPM-B
### TPM-B
tpmcopy --mode import --parentKeyType=rsa \
 --in=/tmp/out.json --out=/tmp/tpmkey.pem \
 --pubout=/tmp/pub.dat --privout=/tmp/priv.dat \
  --parent=0x81008000 --tpm-path=$TPMB

tpmcopy --mode evict \
    --persistentHandle=0x81008001 \
   --in=/tmp/tpmkey.pem --tpm-path=$TPMB

### or using tpm2_tools:
# tpm2_createek -c ek.ctx -G rsa -u ek.pub 
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
# tpm2 startauthsession --session session.ctx --policy-session
# tpm2 policysecret --session session.ctx --object-context endorsement
# tpm2_load -C ek.ctx -c key.ctx -u pub.dat -r priv.dat --auth session:session.ctx
# tpm2_evictcontrol -c key.ctx 0x81008001
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

### run 
go run cmd/main.go \
     --svcAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com" \
     --useEKParent --pcrs=23 --tpm-path=127.0.0.1:2341 --persistentHandle 0x81008001 \
       --tpm-path=127.0.0.1:2341
```

### mTLS Workload Identify Federation

To use mTLS, you need to have a private key on the TPM and then issue a trusted certificate to use with that key.

You can set this up by following both

* [mtls TokenSource](https://github.com/salrashid123/mtls-tokensource)

you can generate a key on the tpm and issue a CSR following the partial instructions [here](https://github.com/salrashid123/oauth2?tab=readme-ov-file#b-generate-key-on-tpm-and-export-public-x509-certificate-to-gcp)


then run as 

```bash
$ go run cmd/main.go -useMTLS \
    --keyfilepath=workload-key.pem  \
        --projectNumber=$PROJECT_NUMBER  \
           --poolID=$POOL_ID --providerID=$PROVIDER_ID   \
             --pubCert=workload-certificate.crt --tpm-path=$TPMA
```


### Encrypted TPM Sessions

If you want to enable [TPM Encrypted sessions](https://github.com/salrashid123/tpm2/tree/master/tpm_encrypted_session), you should provide the "name" of a trusted key on the TPM for each call.

A trusted key can be the EK Key. You can get the name using `tpm2_tools`:

```bash
tpm2_createek -c primary.ctx -G rsa -u ek.pub -Q
tpm2_readpublic -c primary.ctx -o ek.pem -n name.bin -f pem -Q
xxd -p -c 100 name.bin 
  000bb50d34f6377bb3c2f41a1b4b6094ed6efcd7032d28054566db0766879dad1ee0
```

Then use the hex value returned in the `--tpm-session-encrypt-with-name=` argument.

For example:

```bash
   --tpm-session-encrypt-with-name=000bb50d34f6377bb3c2f41a1b4b6094ed6efcd7032d28054566db0766879dad1ee0
```


You can also derive the "name" from a public key of a known template  see [go-tpm.tpm2_get_name](https://github.com/salrashid123/tpm2/tree/master/tpm2_get_name)


### Testing

Unit test just verifies that a token is returned.  TODO is to validate the token against a gcp api (the oauth2 tokeninfo endopoint wont work because the access token is a self-signed JWT)


Using [swtpm](https://github.com/stefanberger/swtpm)

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

# then specify "127.0.0.1:2321"  as the TPM device path in the examples
# and for tpm2_tools, export the following var
export TPM2TOOLS_TCTI="swtpm:port=2321"

export CICD_SA_EMAIL="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com"
export CICD_SA_PEM=`cat /tmp/key_rsa.pem`

go test -v
```


### Using ASN.1 Specification for TPM 2.0 Key Files

The primary we used happens to be the the specified format described in [ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)  where the template h-2 is described in pg 43 [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r2_10feb2021.pdf)

This specific format allows us to easily use openssl and export the key as PEM.  For reference, see  [tpm2 primarykey for (eg TCG EK Credential Profile H-2 profile](https://gist.github.com/salrashid123/9822b151ebb66f4083c5f71fd4cdbe40)

---

Finally, you may want to restrict access to the TPM device by applying [tpm-udev.rules](https://github.com/salrashid123/tpm2#non-root-access-to-in-kernel-resource-manager-devtpmrm0-usint-tpm2-tss)


