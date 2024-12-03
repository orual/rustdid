use base58::ToBase58;
use k256::{
    elliptic_curve::{pkcs8::EncodePrivateKey, sec1::ToEncodedPoint},
    SecretKey,
};
use rand::rngs::OsRng;

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

fn main() {
    let secret_key = SecretKey::random(&mut OsRng);

    // Get raw private key bytes for multibase encoding
    let private_key_bytes = secret_key.to_bytes().to_vec();

    // Get PKCS8 PEM format for storage
    let private_key_der = secret_key
        .to_pkcs8_der()
        .expect("Failed to encode private key");

    let private_key = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            private_key_der.as_bytes()
        )
    );

    // Get the public key in compressed format
    let public_key = secret_key.public_key();
    let public_key_bytes = public_key
        .to_encoded_point(true) // true = compressed format
        .as_bytes()
        .to_vec();

    let private_key_multibase = encode_private_multibase(&private_key_bytes);
    let public_key_multibase = encode_public_multibase(&public_key_bytes);
    let did_key = format!("did:key:{}", public_key_multibase);

    println!("\nPrivate Key (PKCS8 PEM):");
    println!("{}", private_key);
    println!("\nPrivate Key (Multibase):");
    println!("{}", private_key_multibase);
    println!("\nPublic Key (Multibase):");
    println!("{}", public_key_multibase);
    println!("\nDID Key:");
    println!("{}", did_key);
}
