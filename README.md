# bnk-rsv

## bnk-registration-signing-verification
Full name: bnk-registration-signing-verification. Its function is to enable libraries that import this package to register with the bnk chain in the identity of sgx, as well as to sign information with sgx's private key and verify other sgx encrypted information. In simple terms, it can ensure that the source of the information is from a specific code (enclave hash) in sgx environment.

## usage

The primary functions utilized are:

1. `register_sgx_2` Registration with the bnk chain using the sgx identity.


2. `create_sgx_response_v2` Signing information using sgx's private key.

3. `verify_sgx_response_and_restore_origin_response_v2` Verification of other sgx encrypted information. 
During the verification process, it is also necessary to obtain the registration information of the other party's sgx device from the chain by calling `update_relate_device_id_once`

other usages:

`sealing, unsealing` It can also use the sgx private key to encrypt and save data.

