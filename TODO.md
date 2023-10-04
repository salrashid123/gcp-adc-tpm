## TODO's

* Load from files

  instead of persistent handles, use loadable keys from file.

  see:  [go-tpm-tools#349](https://github.com/google/go-tpm-tools/issues/349) 
  
  and [chained keys](https://github.com/salrashid123/tpm2/tree/master/context_chain)


* support [JWTAccessTokens](https://developers.google.com/identity/protocols/oauth2/service-account#jwt-auth)

  this prevents one roundtrip to GCP and allows for very specific "scopes"

  see [oauth2.TPMTokenSource](https://github.com/salrashid123/oauth2/blob/master/README.md#usage-tpmtokensource)

  [openssl TPM based tokens for GCP](https://github.com/salrashid123/tpm2_evp_sign_decrypt#jwtaccess-token-for-gcp-authentication)
