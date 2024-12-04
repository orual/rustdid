use base58::FromBase58;
use base64::Engine;
use k256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    SecretKey,
};
use serde::{Deserialize, Serialize};
use smol::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

use crate::{context::SetupContext, errors::SetupResult};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetupConfig {
    pub domain: String,
    pub pds_host: String,
    pub did_document: DidDocument,
    #[serde(with = "time::serde::timestamp")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub service: Vec<Service>,
}

#[derive(Debug, Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

#[derive(Debug, Serialize)]
struct JwtClaims {
    iss: String,
    aud: String,
    exp: u64,
    iat: u64,
}

impl SetupConfig {
    pub async fn save(&self, path: &PathBuf) -> SetupResult<()> {
        let content = serde_json::to_string_pretty(self)
            .with_config_context("Failed to serialize configuration")?;

        fs::write(path, content)
            .await
            .with_fs_context(path, "write config to")?;

        Ok(())
    }
}

impl DidDocument {
    pub fn new(domain: &str, pds_host: &str, public_key_multibase: &str) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/multikey/v1".to_string(),
                "https://w3id.org/security/suites/secp256k1-2019/v1".to_string(),
            ],
            id: format!("did:web:{}", domain),
            also_known_as: vec![format!("at://{}", domain)],
            verification_method: vec![VerificationMethod {
                id: format!("did:web:{}#atproto", domain),
                key_type: "Multikey".to_string(),
                controller: format!("did:web:{}", domain),
                public_key_multibase: public_key_multibase.to_string(),
            }],
            service: vec![Service {
                id: "#atproto_pds".to_string(),
                service_type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: pds_host.trim_end_matches('/').to_string(),
            }],
        }
    }

    pub async fn save(&self, path: &PathBuf) -> SetupResult<()> {
        let content = serde_json::to_string_pretty(self)
            .with_document_context("Failed to serialize DID document")?;

        fs::write(path, content)
            .await
            .with_fs_context(path, "write DID document to")?;

        Ok(())
    }
}

fn encode_jwt_part<T: Serialize>(value: &T) -> SetupResult<String> {
    let json = serde_json::to_vec(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
        .with_document_context("Failed to serialize JWT part")?;

    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
}

fn load_signing_key(key_data: &str) -> SetupResult<SigningKey> {
    // Parse multibase-encoded private key
    let decoded = key_data[1..]
        .from_base58()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{:?}", e)))
        .with_document_context("Invalid multibase encoding")?;

    // Skip multicodec prefix (0x8126)
    if decoded.len() < 34 || decoded[0] != 0x81 || decoded[1] != 0x26 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid multicodec prefix",
        ))
        .with_document_context("Invalid key format")?;
    }

    // Extract the raw key bytes (skip the multicodec prefix)
    let key_bytes = &decoded[2..];

    // Create signing key from secret key
    let secret_key = SecretKey::from_slice(key_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
        .with_document_context("Failed to create secret key")?;

    Ok(SigningKey::from(secret_key))
}

pub async fn generate_service_auth(
    issuer: &str,
    audience: &str,
    private_key: &str,
) -> SetupResult<String> {
    // Create header
    let header = JwtHeader {
        alg: "ES256K".to_string(),
        typ: "JWT".to_string(),
    };
    let header_encoded = encode_jwt_part(&header)?;

    // Create claims
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        .with_document_context("Failed to get current time")?
        .as_secs();

    let claims = JwtClaims {
        iss: issuer.to_string(),
        aud: audience.to_string(),
        exp: now + 300, // 5 minutes expiry
        iat: now,
    };
    let claims_encoded = encode_jwt_part(&claims)?;

    // Create signature input
    let signature_input = format!("{}.{}", header_encoded, claims_encoded);

    // Sign the input
    let signing_key = load_signing_key(private_key)?;
    let signature: Signature = signing_key.sign(signature_input.as_bytes());

    // Encode signature
    let signature_encoded =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_der());

    // Combine all parts
    Ok(format!(
        "{}.{}.{}",
        header_encoded, claims_encoded, signature_encoded
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn generate_test_key() -> String {
        let secret_key = SecretKey::random(&mut OsRng);
        let key_bytes = secret_key.to_bytes();

        let mut encoded = vec![0x81, 0x26];
        encoded.extend_from_slice(key_bytes.as_ref());
        format!("z{}", base58::ToBase58::to_base58(&encoded[..]))
    }

    #[test]
    fn test_key_format() {
        let test_key = generate_test_key();

        // Test that we can load the key
        let result = load_signing_key(&test_key);
        assert!(result.is_ok(), "Failed to load test key");

        // Verify the key format
        assert!(
            test_key.starts_with('z'),
            "Key should start with multibase prefix 'z'"
        );

        let decoded = test_key[1..].from_base58().unwrap();
        assert_eq!(&decoded[0..2], &[0x81, 0x26], "Invalid multicodec prefix");
        assert_eq!(decoded.len(), 34, "Invalid key length"); // 2 bytes prefix + 32 bytes key
    }

    #[test]
    fn test_did_document_creation() {
        let domain = "example.com";
        let pds_host = "https://pds.example.com";
        let public_key = "zDnaegSamplePublicKey123";

        let doc = DidDocument::new(domain, pds_host, public_key);

        assert_eq!(doc.id, "did:web:example.com");
        assert_eq!(doc.also_known_as, vec!["at://example.com"]);
        assert_eq!(doc.verification_method[0].public_key_multibase, public_key);
        assert_eq!(doc.service[0].service_endpoint, pds_host);
    }

    #[test]
    fn test_did_document_serialization() {
        let doc = DidDocument::new(
            "example.com",
            "https://pds.example.com",
            "zDnaegSamplePublicKey123",
        );

        let json = serde_json::to_value(&doc).unwrap();

        assert_eq!(
            json["@context"],
            serde_json::json!([
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
                "https://w3id.org/security/suites/secp256k1-2019/v1"
            ])
        );
        assert_eq!(json["id"], "did:web:example.com");
        assert_eq!(json["alsoKnownAs"], serde_json::json!(["at://example.com"]));
        assert!(json["verificationMethod"][0]["type"] == "Multikey");
    }

    #[test]
    fn test_service_auth_generation() {
        smol::block_on(async {
            let test_key = generate_test_key();

            let result =
                generate_service_auth("did:web:example.com", "did:web:pds.example.com", &test_key)
                    .await;

            assert!(
                result.is_ok(),
                "Failed to generate service auth token: {:?}",
                result.err()
            );

            let token = result.unwrap();
            let parts: Vec<&str> = token.split('.').collect();

            assert_eq!(parts.len(), 3, "Invalid JWT structure");

            // Verify header
            let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[0])
                .unwrap();
            let header_json: serde_json::Value =
                serde_json::from_str(&String::from_utf8(header).unwrap()).unwrap();
            assert_eq!(header_json["alg"], "ES256K");
            assert_eq!(header_json["typ"], "JWT");

            // Verify claims
            let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .unwrap();
            let claims_json: serde_json::Value =
                serde_json::from_str(&String::from_utf8(claims).unwrap()).unwrap();
            assert_eq!(claims_json["iss"], "did:web:example.com");
            assert_eq!(claims_json["aud"], "did:web:pds.example.com");
            assert!(claims_json["exp"].is_number());
            assert!(claims_json["iat"].is_number());
        });
    }

    #[test]
    fn test_did_document_save() {
        smol::block_on(async {
            let temp_dir = tempdir().unwrap();
            let did_path = temp_dir.path().join("did.json");

            let doc = DidDocument::new(
                "example.com",
                "https://pds.example.com",
                "zDnaegSamplePublicKey123",
            );

            assert!(doc.save(&did_path).await.is_ok());

            let content = fs::read_to_string(&did_path).await.unwrap();
            let loaded_doc: DidDocument = serde_json::from_str(&content).unwrap();
            assert_eq!(loaded_doc.id, doc.id);
            assert_eq!(
                loaded_doc.verification_method[0].public_key_multibase,
                doc.verification_method[0].public_key_multibase
            );
        });
    }
}
