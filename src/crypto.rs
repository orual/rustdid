use crate::{context::SetupContext, errors::SetupResult};
use base58::ToBase58;
use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use rand::rngs::OsRng;
use std::path::Path;

pub struct KeyPair {
    pub private_key: String,
    pub public_key_multibase: String,
}

impl KeyPair {
    pub async fn save_to_file(&self, path: &Path) -> crate::errors::SetupResult<()> {
        let key_path = path.join("private.key");
        smol::fs::write(&key_path, &self.private_key)
            .await
            .with_fs_context(&key_path, "write private key to")?;
        Ok(())
    }
}


fn encode_private_multibase(data: &[u8]) -> String {
    // multicodec secp256k1-priv, code 0x1301
    let mut encoded = vec![0x81, 0x26];
    encoded.extend_from_slice(data);
    format!("z{}", encoded.to_base58())
}

fn encode_public_multibase(data: &[u8]) -> String {
    // multicodec secp256k1-pub, code 0xE7
    let mut encoded = vec![0xE7, 0x01];
    encoded.extend_from_slice(data);
    format!("z{}", encoded.to_base58())
}

pub async fn generate_keypair() -> SetupResult<KeyPair> {
    // Generate the private key
    let secret_key = SecretKey::random(&mut OsRng);

    // Get raw private key bytes for multibase encoding
    let private_key_bytes = secret_key.to_bytes().to_vec();
    let private_key_multibase = encode_private_multibase(&private_key_bytes);

    // Get the public key in compressed format
    let public_key = secret_key.public_key();
    let public_key_bytes = public_key
        .to_encoded_point(true) // true = compressed format
        .as_bytes()
        .to_vec();

    let public_key_multibase = encode_public_multibase(&public_key_bytes);

    Ok(KeyPair {
        private_key: private_key_multibase,
        public_key_multibase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multibase_encoding() {
        // Test private key multibase encoding
        let test_priv = vec![0x01, 0x02, 0x03, 0x04];
        let encoded_priv = encode_private_multibase(&test_priv);
        assert!(encoded_priv.starts_with('z'));
        let decoded_priv = base58::FromBase58::from_base58(&encoded_priv[1..]).unwrap();
        assert_eq!(&decoded_priv[..2], &[0x81, 0x26]); // secp256k1-priv prefix
        assert_eq!(&decoded_priv[2..], &test_priv);

        // Test public key multibase encoding
        let test_pub = vec![0x02, 0x01, 0x02, 0x03]; // Note 0x02 prefix for compressed point
        let encoded_pub = encode_public_multibase(&test_pub);
        assert!(encoded_pub.starts_with('z'));
        let decoded_pub = base58::FromBase58::from_base58(&encoded_pub[1..]).unwrap();
        assert_eq!(&decoded_pub[..2], &[0xE7, 0x01]); // secp256k1-pub prefix
        assert_eq!(&decoded_pub[2..], &test_pub);
    }

    #[test]
    fn test_keypair_generation() {
        smol::block_on(async {
            let result = generate_keypair().await;
            assert!(result.is_ok(), "Failed to generate keypair");

            let keypair = result.unwrap();

            // Test private key format
            assert!(keypair.private_key.starts_with('z'));
            let decoded_priv = base58::FromBase58::from_base58(&keypair.private_key[1..]).unwrap();
            assert_eq!(&decoded_priv[..2], &[0x81, 0x26]); // secp256k1-priv prefix
            assert_eq!(decoded_priv.len(), 34); // prefix + private key (32 bytes)

            // Test public key format
            assert!(keypair.public_key_multibase.starts_with('z'));
            let decoded_pub =
                base58::FromBase58::from_base58(&keypair.public_key_multibase[1..]).unwrap();
            assert_eq!(&decoded_pub[..2], &[0xE7, 0x01]); // secp256k1-pub prefix
            assert!(decoded_pub[2] == 0x02 || decoded_pub[2] == 0x03); // Compressed point format
            assert_eq!(decoded_pub.len(), 35); // prefix + compressed point (33 bytes)
        });
    }
}
