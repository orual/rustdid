use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use smol::fs;
use std::path::PathBuf;
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
struct ServiceAuthClaims {
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
}

enum SecretType {
    Plain,
    Pem,
    Der,
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
                service_endpoint: pds_host.to_string(),
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

fn detect_secret_type(secret: &[u8]) -> SecretType {
    if secret.starts_with(b"-----BEGIN") {
        SecretType::Pem
    } else if !secret.is_empty() && secret[0] == 0x30 {
        SecretType::Der
    } else {
        SecretType::Plain
    }
}

fn load_ec_key(key_data: &[u8]) -> SetupResult<EncodingKey> {
    match detect_secret_type(key_data) {
        SecretType::Pem => {
            EncodingKey::from_ec_pem(key_data).with_keypair_context("Invalid EC PEM key format")
        }
        SecretType::Der => Ok(EncodingKey::from_ec_der(key_data)),
        SecretType::Plain => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Raw key data not supported for ES256",
        ))
        .with_keypair_context("Unsupported key format")?,
    }
}

pub async fn generate_service_auth(
    issuer: &str,
    audience: &str,
    private_key: &str,
) -> SetupResult<String> {
    let now = OffsetDateTime::now_utc();
    let exp = now + time::Duration::minutes(5);

    let claims = ServiceAuthClaims {
        iss: issuer.to_string(),
        aud: audience.to_string(),
        exp: exp.unix_timestamp(),
        iat: now.unix_timestamp(),
    };

    let mut header = Header::new(Algorithm::ES256);
    header.typ = None;

    let key = load_ec_key(private_key.as_bytes())?;

    encode(&header, &claims, &key).with_document_context("Failed to generate JWT token")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const TEST_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMUplEH9KyymJ+b5Z
eWUJXwb09fEhBZdUcF+Z3L52zYOhRANCAAT05IS6H4HpvXCDyMefgguNgsjTwy7y
TWdyNCIIeYoOkBOKsiLFfOC1DFdFoi0TnUI/bs7OMCXJX2g5D/y41RTD
-----END PRIVATE KEY-----"#;

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
            let result =
                generate_service_auth("did:web:example.com", "did:web:pds.example.com", TEST_PEM)
                    .await;

            assert!(
                result.is_ok(),
                "Failed to generate service auth token: {:?}",
                result.err()
            );
            let token = result.unwrap();

            let parts: Vec<&str> = token.split('.').collect();
            assert_eq!(parts.len(), 3, "Invalid JWT structure");

            let header =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[0])
                    .unwrap();
            let header_json: serde_json::Value =
                serde_json::from_str(&String::from_utf8(header).unwrap()).unwrap();
            assert_eq!(header_json["alg"], "ES256");
            assert!(!header_json.as_object().unwrap().contains_key("typ"));

            let claims =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
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
