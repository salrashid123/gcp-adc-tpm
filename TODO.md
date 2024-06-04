## TODO's

* support [JWTAccessTokens](https://developers.google.com/identity/protocols/oauth2/service-account#jwt-auth)

  this prevents one roundtrip to GCP and allows for very specific "scopes"

  see [oauth2.TPMTokenSource](https://github.com/salrashid123/oauth2/blob/master/README.md#usage-tpmtokensource)

  [openssl TPM based tokens for GCP](https://github.com/salrashid123/tpm2_evp_sign_decrypt#jwtaccess-token-for-gcp-authentication)
