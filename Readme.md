# JWT Builder and Validator

This Python script demonstrates how to create and validate JSON Web Tokens (JWTs) using HMAC or RSA algorithms for signing and RSA for encryption.

## Features

- **JwtBuilder**: Builds a JWT with specified claims, signing key, and encryption key.
- **is_valid**: Validates a JWT's signature and expiration time.
- **RSAEncryption**: Encrypts and decrypts JWT claims using RSA keys.
- **AlgorithmFactory**: Factory method to choose between HMAC and RSA signing algorithms.

## Dependencies

- Python 3.x
- `rsa` library (install via `pip install rsa`)
- `PyYAML` library (install via `pip install PyYAML`)

## Usage

1. **Generate RSA Keys:**
   ```python
   rsa_keys = RSAKeys.generate_keys()
   e_keys = RSAKeys.generate_keys()

   rsa_encryption = RSAEncryption()
   rsa_signing = RSAAlgorithm(RSAKeys(rsa_keys.pub_key, rsa_keys.pvt_key))

   jwt_builder = JwtBuilder(
       jre=rsa_encryption,
       claims=claims_dict,
       signing_key=rsa_signing.pvt,
       encrypting_key=e_keys.pub_key,
       signing=rsa_signing
   )

   jwt_token = jwt_builder.build()

   decoded_status, decoded_claims = decode_claims(jwt_token, "rsa", rsa_keys.pub_key, e_keys.pvt_key, 1000, rsa_keys.pvt_key)
   if decoded_status == JwtStatus.VALID_OK:
       print("Decoded Claims:", decoded_claims)
