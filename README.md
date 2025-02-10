### TPM Credential Source for Google Cloud SDK

Binary that just returns a Service Accounts `access_token` for use with GCP Credential Libraries where the key is accessed using direct calls to a `Trusted Platform Module` (TPM).

While not running on a GCP platform like GCE, Cloud Run, GCF or GKE, `Service Account` authentication usually (with exception of workload federation) requires direct access to its RSA Private key.. 

You can see why here in the protocol itself in [AIP-4111: Self-signed JWT with Scopes](https://google.aip.dev/auth/4111).  Basically service account authentication involves locally signing a JWT and using that directly as an  `access_token`.

What this repo offers is a way to generate the JWT while the RSA key is embedded on a TPM and then use it to issue GCP `access_tokens`

There are several ways to embed a GCP Service Account into a TPM.  

1. download a Google ServiceAccount's json file and embed the private part to the TPM or
2. Generate a Key ON THE TPM and then import the public part to GCP. or
3. remote seal the service accounts RSA Private key remotely, encrypt it with the remote TPM's Endorsement Key and load it

These are described here: [oauth2 TPM TokenSource](https://github.com/salrashid123/oauth2/blob/master/README.md#usage-tpmtokensource)

This specific demo here will use option (1) which is the easiest but ultimately, you just need a reference handle to the TPM which all three options can provide.

> *NOTE* While this repo is a CLI,  you can acquire an embedded service account's token for use with a library as an [oauth2 TPM TokenSource](https://github.com/salrashid123/oauth2/blob/master/README.md#usage-tpmtokensource)

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

| Option | Description |
|:------------|-------------|
| **`--tpm-path`** | path to the TPM device (default: `/dev/tpm0`) |
| **`--persistentHandle`** | Persistent Handle for the HMAC key (default: `0x81010002`) |
| **`--keyfilepath`** | Path to the TPM HMAC credential file (default: ``) |
| **`--svcAccountEmail`** | (required) Service Account Email |
| **`--parentPass`** | Passphrase for the owner handle (will use TPM_PARENT_AUTH env var) |
| **`--keyPass`** | Passphrase for the key handle (will use TPM_KEY_AUTH env var) |
| **`--pcrs`** | "PCR Bound value (increasing order, comma separated)" |
| **`--scopes`** |  "comma separated scopes (default `https://www.googleapis.com/auth/cloud-platform`)" |
| **`--expireIn`** | "How many seconds the token is valid for" |
| **`--tpm-session-encrypt-with-name`** | hex encoded TPM object 'name' to use with an encrypted session |

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

```bash
CGO_ENABLED=0 go build -o gcp-adc-tpm adc.go

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


### Using ASN.1 Specification for TPM 2.0 Key Files

The primary we used happens to be the the specified format described in [ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)  where the template h-2 is described in pg 43 [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r2_10feb2021.pdf)

This specific format allows us to easily use openssl and export the key as PEM.  For reference, see  [tpm2 primarykey for (eg TCG EK Credential Profile H-2 profile](https://gist.github.com/salrashid123/9822b151ebb66f4083c5f71fd4cdbe40)

---

Finally, you may want to restrict access to the TPM device by applying [tpm-udev.rules](https://github.com/salrashid123/tpm2#non-root-access-to-in-kernel-resource-manager-devtpmrm0-usint-tpm2-tss)


