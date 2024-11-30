use base58::ToBase58;
use base64::Engine;
use crate::context::SetupContext;
use crate::errors::SetupResult;
use futures_lite::AsyncWriteExt;
use smol::process::{Command, Stdio};

pub struct KeyPair {
    pub private_key: String,
    pub public_key_multibase: String,
}

fn encode_multibase(data: &[u8]) -> String {
    // Format is "z" + base58btc(0x1200 + raw key data)
    let mut encoded = vec![0x12, 0x00];
    encoded.extend_from_slice(data);
    format!("z{}", encoded.to_base58())
}

pub async fn generate_keypair() -> SetupResult<KeyPair> {
    // Generate private key using NIST P-256 curve
    let private_key = Command::new("openssl")
        .args(["ecparam", "-name", "prime256v1", "-genkey", "-noout"])
        .output()
        .await
        .with_keypair_context("Failed to generate private key")?;

    // Convert to PKCS8 format
    let mut pkcs8_cmd = Command::new("openssl")
        .args(["pkcs8", "-topk8", "-nocrypt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_keypair_context("Failed to start PKCS8 conversion")?;

    if let Some(mut stdin) = pkcs8_cmd.stdin.take() {
        stdin.write_all(&private_key.stdout)
            .await
            .with_keypair_context("Failed to write to PKCS8 process")?;
        stdin.flush()
            .await
            .with_keypair_context("Failed to flush PKCS8 input")?;
    }

    let output = pkcs8_cmd.output()
        .await
        .with_keypair_context("Failed to complete PKCS8 conversion")?;

    let private_key_pkcs8 = String::from_utf8(output.stdout)
        .with_keypair_context("Invalid UTF-8 in private key")?;

    // Extract public key
    let mut pubkey_cmd = Command::new("openssl")
        .args(["ec", "-pubout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_keypair_context("Failed to start public key extraction")?;

    if let Some(mut stdin) = pubkey_cmd.stdin.take() {
        stdin.write_all(private_key_pkcs8.as_bytes())
            .await
            .with_keypair_context("Failed to write to public key process")?;
        stdin.flush()
            .await
            .with_keypair_context("Failed to flush public key input")?;
    }

    let output = pubkey_cmd.output()
        .await
        .with_keypair_context("Failed to extract public key")?;

    // Extract raw public key bytes and encode in multibase format
    let pub_key_raw = extract_raw_public_key(&output.stdout)
        .with_keypair_context("Failed to extract raw public key")?;

    let public_key_multibase = encode_multibase(&pub_key_raw);

    Ok(KeyPair {
        private_key: private_key_pkcs8,
        public_key_multibase,
    })
}

fn extract_raw_public_key(pem_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    // Parse PEM to get DER data
    let pem = String::from_utf8(pem_data.to_vec())
        .map_err(|_| "Invalid UTF-8 in PEM data")?;

    let der_base64 = pem.lines()
        .filter(|line| !line.contains("BEGIN") && !line.contains("END"))
        .collect::<String>();

    let der_data = base64::engine::general_purpose::STANDARD
        .decode(der_base64.trim())
        .map_err(|_| "Invalid base64 in PEM data")?;

    // Extract the actual public key point from the DER structure
    // For P-256, the key is 65 bytes: 0x04 followed by 32-byte X and Y coordinates
    if der_data.len() < 89 {
        return Err("DER data too short");
    }

    // The public key point is at the end of the DER structure
    Ok(der_data[der_data.len() - 65..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multibase_encoding() {
        let test_data = vec![0x04, 0x01, 0x02, 0x03];
        let encoded = encode_multibase(&test_data);
        assert!(encoded.starts_with('z'));

        // Verify the prefix bytes
        let decoded = base58::FromBase58::from_base58(&encoded[1..]).unwrap();
        assert_eq!(&decoded[2..], &test_data);
        assert_eq!(&decoded[..2], &[0x12, 0x00]);
    }

    #[test]
    fn test_keypair_generation() {
        smol::block_on(async {
            let result = generate_keypair().await;
            assert!(result.is_ok());

            let keypair = result.unwrap();
            assert!(keypair.private_key.contains("BEGIN PRIVATE KEY"));
            assert!(keypair.private_key.contains("END PRIVATE KEY"));
            assert!(keypair.public_key_multibase.starts_with('z'));

            // Verify multibase encoding structure
            let decoded = base58::FromBase58::from_base58(&keypair.public_key_multibase[1..]).unwrap();
            assert_eq!(&decoded[..2], &[0x12, 0x00]);
            assert_eq!(decoded[2], 0x04); // Uncompressed point format
            assert_eq!(decoded.len(), 67); // 0x1200 + 65 bytes public key
        });
    }
}
