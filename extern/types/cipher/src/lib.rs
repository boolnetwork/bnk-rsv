use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
pub struct Encrypt;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidVersion,
    InvalidSalt,
    KeyEncryption,
}

// "cipher": "aes-256-gcm"
impl Encrypt {
    pub const NONCE_KEY: &'static [u8] = b"bool network";
    pub const ROUNDS: u8 = 13;

    pub fn encrypt(password: &str, secret: Vec<u8>) -> Result<Vec<u8>, Error> {
        let salt = {
            let mut salt: [u8; 16] = [0; 16];
            OsRng.fill_bytes(&mut salt);
            salt
        };
        let key = Self::password_to_key(password, &salt, Self::ROUNDS)?;
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(Self::NONCE_KEY);

        // placeholder for key security
        let associated_data: Vec<u8> = vec![1];
        let payload = Payload {
            msg: &secret,
            aad: &associated_data,
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| Error::KeyEncryption)?;

        let mut concat: Vec<u8> = Vec::new();
        concat.push(0x1); // 1 byte version number
        concat.extend(salt); // 16 bytes of salt
        concat.extend(associated_data); // 1 byte of key security
        concat.extend(ciphertext); // ciphertext
        Ok(concat)
    }

    pub fn decrypt(password: &str, encrypted: Vec<u8>) -> Result<Vec<u8>, Error> {
        let version: u8 = encrypted[0];
        if version != 1 {
            return Err(Error::InvalidVersion);
        }
        let salt: [u8; 16] = encrypted[1..1 + 16]
            .try_into()
            .map_err(|_e| Error::InvalidSalt)?;
        let associated_data = &encrypted[1 + 16..1 + 16 + 1];
        let ciphertext = &encrypted[1 + 16 + 1..];
        let key = Self::password_to_key(password, &salt, Self::ROUNDS)?;
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(Self::NONCE_KEY);

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| Error::KeyEncryption)?;
        if associated_data.is_empty() {
            return Err(Error::KeyEncryption);
        }

        let key_security = associated_data[0];
        if key_security != 1 {
            return Err(Error::KeyEncryption);
        }

        Ok(plaintext)
    }

    // Hash password into a 32-byte (256-bit) key
    fn password_to_key(password: &str, salt: &[u8; 16], log_n: u8) -> Result<[u8; 32], Error> {
        let params = scrypt::Params::new(log_n, 8, 1, 32).map_err(|_e| Error::KeyEncryption)?;
        let mut key: [u8; 32] = [0; 32];
        if scrypt::scrypt(password.as_bytes(), salt, &params, &mut key).is_err() {
            return Err(Error::KeyEncryption);
        }
        Ok(key)
    }
}

#[test]
fn test_aes() {
    let password = "hello_world";
    let data = [4; 32].to_vec();
    let ciphertext = Encrypt::encrypt(password, data.clone()).unwrap();
    println!("len: {}", ciphertext.len());
    let plaintext = Encrypt::decrypt(password, ciphertext.clone()).unwrap();
    assert_eq!(data, plaintext);

    let ret = Encrypt::decrypt("hello world", ciphertext.clone());
    assert_eq!(ret, Err(Error::KeyEncryption));

    let mut mock_ciphertext = ciphertext.clone();
    mock_ciphertext[0] = 2;
    let ret = Encrypt::decrypt(password, mock_ciphertext);
    assert_eq!(ret, Err(Error::InvalidVersion));

    let mut mock_ciphertext = ciphertext;
    mock_ciphertext[2] += 1;
    let ret = Encrypt::decrypt(password, mock_ciphertext);
    assert_eq!(ret, Err(Error::KeyEncryption));
}
