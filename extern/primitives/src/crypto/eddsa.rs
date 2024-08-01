use sp_std::convert::TryFrom;

/// Verify ed25519 signature
pub fn ed25519_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use sp_core::ed25519::{Public, Signature};

    let pk = match Public::try_from(pubkey) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let signature = match Signature::try_from(sig) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    sp_io::crypto::ed25519_verify(&signature, msg, &pk)
}