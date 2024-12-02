use crate::{context::SetupContext, did::DidDocument, errors::SetupResult};
use serde::{Deserialize, Serialize};
use surf::{http::headers::AUTHORIZATION, Client, Config};

#[derive(Debug, Serialize)]
pub struct CreateAccountParams {
    pub pds_host: String,
    pub handle: String,
    pub password: String,
    pub email: Option<String>,
    pub existing_did: Option<String>,
    pub service_auth: String,
    pub invite_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateAccountRequest {
    handle: String,
    password: String,
    email: Option<String>,
    did: Option<String>,
    #[serde(rename = "inviteCode")]
    invite_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct CreateAccountResponse {
    did: String,
    pub handle: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct CreateSessionResponse {
    #[serde(rename = "accessJwt")]
    access_jwt: String,
    #[serde(rename = "refreshJwt")]
    refresh_jwt: String,
    did: String,
    handle: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PlcResponse {
    #[serde(rename = "alsoKnownAs")]
    also_known_as: Vec<String>,
    #[serde(rename = "verificationMethods")]
    pub verification_methods: std::collections::HashMap<String, String>,
    #[serde(rename = "rotationKeys")]
    rotation_keys: Vec<String>,
    services: std::collections::HashMap<String, Service>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Service {
    #[serde(rename = "type")]
    service_type: String,
    endpoint: String,
}

pub struct AtProto {
    client: Client,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

impl AtProto {
    pub fn new() -> Self {
        let config = Config::new().set_timeout(Some(std::time::Duration::from_secs(30)));

        Self {
            client: config.try_into().expect("Failed to create HTTP client"),
            access_token: None,
            refresh_token: None,
        }
    }

    pub async fn resolve_identifier(&self, identifier: &str) -> SetupResult<DidDocument> {
        let url = if identifier.contains("://") {
            format!("{}/.well-known/did.json", identifier)
        } else {
            format!("https://{}/.well-known/did.json", identifier)
        };

        let mut response = self
            .client
            .get(&url)
            .await
            .with_document_context(format!("Failed to resolve identifier: {}", identifier))?;

        let doc: DidDocument = response
            .body_json()
            .await
            .with_document_context("Failed to parse DID document")?;

        Ok(doc)
    }

    pub async fn create_account(
        &self,
        params: CreateAccountParams,
    ) -> SetupResult<CreateAccountResponse> {
        let req = CreateAccountRequest {
            handle: params.handle,
            password: params.password,
            email: params.email,
            did: params.existing_did,
            invite_code: params.invite_code,
        };

        let url = format!("{}/xrpc/com.atproto.server.createAccount", params.pds_host);
        let mut response = self
            .client
            .post(&url)
            .header(AUTHORIZATION, format!("Bearer {}", params.service_auth))
            .body_json(&req)
            .with_document_context("Failed to create request body")?
            .await
            .with_document_context("Failed to send request to PDS")?;

        let account: CreateAccountResponse = response
            .body_json()
            .await
            .with_document_context("Failed to parse PDS response")?;

        Ok(account)
    }

    pub async fn login(
        &mut self,
        pds_host: &str,
        handle: &str,
        password: &str,
    ) -> SetupResult<CreateSessionResponse> {
        let url = format!("{}/xrpc/com.atproto.server.createSession", pds_host);
        let mut response = self
            .client
            .post(&url)
            .body_json(&serde_json::json!({
                "identifier": handle,
                "password": password
            }))
            .with_document_context("Failed to create login request")?
            .await
            .with_document_context("Failed to log in to PDS")?;

        let session: CreateSessionResponse = response
            .body_json()
            .await
            .with_document_context("Failed to parse login response")?;

        self.access_token = Some(session.access_jwt.clone());
        self.refresh_token = Some(session.refresh_jwt.clone());

        Ok(session)
    }

    pub async fn activate_account(&self, pds_host: &str) -> SetupResult<()> {
        let access_token = self
            .access_token
            .as_ref()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Must login before activating account",
                )
            })
            .with_document_context("No active session")?;

        let url = format!("{}/xrpc/com.atproto.server.activateAccount", pds_host);
        let response = self
            .client
            .post(&url)
            .header(AUTHORIZATION, format!("Bearer {}", access_token))
            .await
            .with_document_context("Failed to activate account")?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to activate account: {}", response.status()),
            ))
            .with_document_context("PDS returned error status")?
        }
    }

    pub async fn get_plc_recommended(&self, pds_host: &str) -> SetupResult<PlcResponse> {
        let access_token = self
            .access_token
            .as_ref()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Must login before getting PLC config",
                )
            })
            .with_document_context("No active session")?;

        let url = format!(
            "{}/xrpc/com.atproto.identity.getRecommendedDidCredentials",
            pds_host
        );
        let mut response = self
            .client
            .get(&url)
            .header(AUTHORIZATION, format!("Bearer {}", access_token))
            .await
            .with_document_context("Failed to get PLC config")?;

        let config: PlcResponse = response
            .body_json()
            .await
            .with_document_context("Failed to parse PLC config")?;

        Ok(config)
    }

    pub async fn verify_invite_code(&self, pds_host: &str, invite_code: &str) -> SetupResult<bool> {
        let url = format!("{}/xrpc/com.atproto.server.checkInviteCode", pds_host);

        let response = self
            .client
            .post(&url)
            .body_json(&serde_json::json!({
                "code": invite_code
            }))
            .with_document_context("Failed to create invite code request")?
            .await
            .with_document_context("Failed to verify invite code")?;

        Ok(response.status().is_success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_resolve_identifier() {
        smol::block_on(async {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:web:test.com",
                    "alsoKnownAs": ["at://test.com"],
                    "verificationMethod": [{
                        "id": "did:web:test.com#atproto",
                        "type": "Multikey",
                        "controller": "did:web:test.com",
                        "publicKeyMultibase": "zQ3shXjHeiBuRCKmM36cuYnm7YEMzhXCZzqxQhJDEiiDZsJ9d"
                    }],
                    "service": [{
                        "id": "#atproto_pds",
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": "https://pds.test.com"
                    }]
                })))
            .mount(&mock_server)
            .await;

            let client = AtProto::new();
            // Pass the full mock server URL including protocol
            let result = client.resolve_identifier(&mock_server.uri()).await;
            assert!(
                result.is_ok(),
                "Failed to resolve identifier: {:?}",
                result.err()
            );

            let doc = result.unwrap();
            assert_eq!(doc.id, "did:web:test.com");
        });
    }

    #[test]
    fn test_account_creation() {
        smol::block_on(async {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/xrpc/com.atproto.server.createAccount"))
                .and(header("Authorization", "Bearer test-auth"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "did": "did:web:test.com",
                    "handle": "test.com"
                })))
                .mount(&mock_server)
                .await;

            let client = AtProto::new();
            let create_params = CreateAccountParams {
                pds_host: mock_server.uri(),
                handle: "test.com".to_string(),
                password: "password123".to_string(),
                email: None,
                existing_did: Some("did:web:test.com".to_string()),
                service_auth: "test-auth".to_string(),
                invite_code: Some("bsky-social-XXXXX-XXXXX".to_string()),
            };

            let result = client.create_account(create_params).await;
            assert!(result.is_ok());

            let account = result.unwrap();
            assert_eq!(account.did, "did:web:test.com");
            assert_eq!(account.handle, "test.com");
        });
    }

    #[test]
    fn test_login_and_activation() {
        smol::block_on(async {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/xrpc/com.atproto.server.createSession"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "accessJwt": "test-token",
                    "refreshJwt": "test-refresh",
                    "handle": "test.com",
                    "did": "did:web:test.com"
                })))
                .mount(&mock_server)
                .await;

            Mock::given(method("POST"))
                .and(path("/xrpc/com.atproto.server.activateAccount"))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&mock_server)
                .await;

            let mut client = AtProto::new();

            let login_result = client
                .login(&mock_server.uri(), "test.com", "password123")
                .await;
            assert!(login_result.is_ok());

            let activate_result = client.activate_account(&mock_server.uri()).await;
            assert!(activate_result.is_ok());
        });
    }

    #[test]
    fn test_get_plc_recommended() {
        smol::block_on(async {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path(
                    "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
                ))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "alsoKnownAs": ["at://test.com"],
                    "verificationMethods": {
                        "atproto": "did:key:ztest123"
                    },
                    "rotationKeys": ["did:key:ztest456"],
                    "services": {
                        "atproto_pds": {
                            "type": "AtprotoPersonalDataServer",
                            "endpoint": "https://pds.test.com"
                        }
                    }
                })))
                .mount(&mock_server)
                .await;

            let mut client = AtProto::new();
            client.access_token = Some("test-token".to_string());

            let result = client.get_plc_recommended(&mock_server.uri()).await;
            assert!(result.is_ok());
            let config = result.unwrap();
            assert_eq!(config.also_known_as[0], "at://test.com");
        });
    }

    #[test]
    fn test_complete_setup_flow() {
        smol::block_on(async {
            let mock_server = MockServer::start().await;
            let base_url = mock_server.uri();

            // Step 1: Resolve the handle
            Mock::given(method("GET"))
                .and(path("/.well-known/did.json"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/json")
                        .set_body_json(serde_json::json!({
                            "@context": ["https://www.w3.org/ns/did/v1"],
                            "id": "did:web:test.com",
                            "alsoKnownAs": ["at://test.com"],
                            "verificationMethod": [{
                                "id": "did:web:test.com#atproto",
                                "type": "Multikey",
                                "controller": "did:web:test.com",
                                "publicKeyMultibase": "zDnaegSampleKey123"
                            }],
                            "service": [{
                                "id": "#atproto_pds",
                                "type": "AtprotoPersonalDataServer",
                                "serviceEndpoint": "https://pds.test.com"
                            }]
                        })),
                )
                .mount(&mock_server)
                .await;

            // Step 2: Create account
            Mock::given(method("POST"))
                .and(path("/xrpc/com.atproto.server.createAccount"))
                .and(header("Authorization", "Bearer test-auth"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "did": "did:web:test.com",
                    "handle": "test.com"
                })))
                .mount(&mock_server)
                .await;

            // Step 3: Login
            Mock::given(method("POST"))
                .and(path("/xrpc/com.atproto.server.createSession"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "accessJwt": "test-token",
                    "refreshJwt": "test-refresh",
                    "handle": "test.com",
                    "did": "did:web:test.com"
                })))
                .mount(&mock_server)
                .await;

            // Step 4: Get PLC config
            Mock::given(method("GET"))
                .and(path(
                    "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
                ))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "alsoKnownAs": ["at://test.com"],
                    "verificationMethods": {
                        "atproto": "did:key:zQ3shjNewKey123"
                    },
                    "rotationKeys": ["did:key:zQ3shqRotationKey123"],
                    "services": {
                        "atproto_pds": {
                            "type": "AtprotoPersonalDataServer",
                            "endpoint": "https://pds.test.com"
                        }
                    }
                })))
                .mount(&mock_server)
                .await;

            // Step 5: Activate account
            Mock::given(method("POST"))
                .and(path("/xrpc/com.atproto.server.activateAccount"))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&mock_server)
                .await;

            // Execute complete flow
            let mut client = AtProto::new();

            // 1. Resolve identifier
            let doc = client.resolve_identifier(&base_url).await.unwrap();
            assert_eq!(doc.id, "did:web:test.com");

            // 2. Create account
            let create_params = CreateAccountParams {
                pds_host: base_url.clone(),
                handle: "test.com".to_string(),
                password: "password123".to_string(),
                email: Some("test@example.com".to_string()),
                existing_did: Some("did:web:test.com".to_string()),
                service_auth: "test-auth".to_string(),
                invite_code: Some("bsky-social-XXXXX-XXXXX".to_string()),
            };

            let account = client.create_account(create_params).await.unwrap();
            assert_eq!(account.did, "did:web:test.com");

            // 3. Login
            let session = client
                .login(&base_url, "test.com", "password123")
                .await
                .unwrap();
            assert_eq!(session.did, "did:web:test.com");

            // 4. Get PLC config
            let plc = client.get_plc_recommended(&base_url).await.unwrap();
            assert!(plc.verification_methods.contains_key("atproto"));

            // 5. Activate account
            assert!(client.activate_account(&base_url).await.is_ok());
        });
    }
}
