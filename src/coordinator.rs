use crate::{
    atproto::{AtProto, CreateAccountParams},
    context::SetupContext,
    crypto::{self, KeyPair},
    did::{self, DidDocument},
    domain,
    errors::{SetupError, SetupResult},
};
use smol::fs;
use std::path::PathBuf;
use time::OffsetDateTime;
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub enum SetupStep {
    Init,
    Domain,
    Pds,
    Keys,
    DidDocument,
    ServiceAuth,
    Account,
    Complete,
}

#[derive(Debug, Clone)]
pub struct AccountParams {
    pub handle: String,
    pub password: String,
    pub email: Option<String>,
    pub invite_code: Option<String>,
}

pub struct SetupCoordinator {
    config_path: PathBuf,
    current_step: SetupStep,
    domain: Option<String>,
    pds_host: Option<String>,
    account_params: Option<AccountParams>,
    keypair: Option<KeyPair>,
    did_document: Option<DidDocument>,
    pub atp_client: AtProto,
    service_auth: Option<String>,
}

impl SetupCoordinator {
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            config_path,
            current_step: SetupStep::Init,
            domain: None,
            pds_host: None,
            account_params: None,
            keypair: None,
            did_document: None,
            atp_client: AtProto::new(),
            service_auth: None,
        }
    }

    pub async fn initialize(&mut self) -> SetupResult<()> {
        if !self.config_path.exists() {
            fs::create_dir_all(&self.config_path)
                .await
                .with_config_context("Failed to create configuration directory")?;
        }
        self.current_step = SetupStep::Domain;
        Ok(())
    }

    pub fn current_step(&self) -> SetupStep {
        self.current_step.clone()
    }

    pub async fn proceed(&mut self) -> SetupResult<()> {
        match self.current_step {
            SetupStep::Init => {
                if !self.config_path.exists() {
                    fs::create_dir_all(&self.config_path)
                        .await
                        .with_document_context("Failed to create config directory")?;
                }
                self.current_step = SetupStep::Domain;
            }
            SetupStep::Domain => {
                if self.domain.is_some() {
                    self.current_step = SetupStep::Pds;
                } else {
                    Err(SetupError::domain(
                        "Domain not set",
                        "Domain must be set before proceeding",
                    ))?
                }
            }
            SetupStep::Pds => {
                if let (Some(domain), Some(pds_host)) = (&self.domain, &self.pds_host) {
                    domain::validate_domain(domain).await?;
                    domain::validate_pds_host(pds_host).await?;
                    domain::check_pds_connection(pds_host).await?;
                    self.current_step = SetupStep::Keys;
                }
            }
            SetupStep::Keys => {
                self.keypair = Some(crypto::generate_keypair().await?);
                if let Some(keypair) = &self.keypair {
                    keypair.save_to_file(&self.config_path).await?;
                }
                self.current_step = SetupStep::DidDocument;
            }
            SetupStep::DidDocument => {
                if let (Some(domain), Some(pds_host), Some(keypair)) =
                    (&self.domain, &self.pds_host, &self.keypair)
                {
                    let doc = DidDocument::new(domain, pds_host, &keypair.public_key_multibase);
                    let did_path = self.config_path.join("did.json");
                    doc.save(&did_path).await?;
                    self.did_document = Some(doc);
                    self.current_step = SetupStep::ServiceAuth;
                }
            }
            SetupStep::ServiceAuth => {
                if let (Some(doc), Some(keypair)) = (&self.did_document, &self.keypair) {
                    let pds_url = Url::parse(self.pds_host.as_ref().unwrap())
                        .map_err(|e| SetupError::url("Failed to parse URL", e.to_string()))?;
                    let pds_did = format!("did:web:{}", pds_url.host_str().unwrap());

                    self.service_auth = Some(
                        did::generate_service_auth(&doc.id, &pds_did, &keypair.private_key).await?,
                    );

                    self.current_step = SetupStep::Account;
                }
            }
            SetupStep::Account => {
                if let (Some(params), Some(doc), Some(service_auth)) =
                    (&self.account_params, &self.did_document, &self.service_auth)
                {
                    let pds_host = self.pds_host.as_ref().unwrap();

                    // Check invite code if provided
                    if let Some(invite_code) = &params.invite_code {
                        self.atp_client
                            .verify_invite_code(pds_host, invite_code)
                            .await?;
                    }

                    // Create account
                    let create_params = CreateAccountParams {
                        pds_host: pds_host.to_string(),
                        handle: params.handle.clone(),
                        password: params.password.clone(),
                        email: params.email.clone(),
                        existing_did: Some(doc.id.clone()),
                        service_auth: service_auth.clone(),
                        invite_code: params.invite_code.clone(),
                    };

                    let account = self.atp_client.create_account(create_params).await?;

                    // Login
                    self.atp_client
                        .login(pds_host, &account.handle, &params.password)
                        .await?;

                    // Get PLC config and update DID document
                    let plc = self.atp_client.get_plc_recommended(pds_host).await?;
                    if let Some(new_key) = plc.verification_methods.get("atproto") {
                        if let Some(key_value) = new_key.strip_prefix("did:key:") {
                            self.did_document.as_mut().unwrap().verification_method[0]
                                .public_key_multibase = key_value.to_string();

                            let did_path = self.config_path.join("did.json");
                            self.did_document.as_ref().unwrap().save(&did_path).await?;
                        }
                    }

                    // Activate account
                    self.atp_client.activate_account(pds_host).await?;

                    // Save final configuration
                    let config = did::SetupConfig {
                        domain: self.domain.clone().unwrap(),
                        pds_host: self.pds_host.clone().unwrap(),
                        did_document: self.did_document.clone().unwrap(),
                        created_at: OffsetDateTime::now_utc(),
                    };
                    let config_path = self.config_path.join("config.json");
                    config
                        .save(&config_path)
                        .await
                        .with_config_context("Failed to save final configuration")?;

                    self.current_step = SetupStep::Complete;
                }
            }
            SetupStep::Complete => {}
        }
        Ok(())
    }

    fn validate_domain(&mut self, domain: &str) -> SetupResult<()> {
        if domain.is_empty() {
            return Err(SetupError::input(
                "Domain cannot be empty",
                "Empty domain provided",
            ))?;
        }

        // No protocol prefixes allowed
        if domain.contains("://") {
            return Err(SetupError::input(
                "Domain should not include protocol",
                "Invalid domain format",
            ))?;
        }

        // Basic DNS validation
        if !domain.contains('.') {
            return Err(SetupError::input(
                "Domain must include at least one dot",
                "Invalid domain format",
            ))?;
        }

        self.domain = Some(domain.to_string());
        Ok(())
    }

    fn validate_pds_host(&self, pds_host: &str) -> SetupResult<()> {
        if pds_host.is_empty() {
            return Err(SetupError::input(
                "PDS host cannot be empty",
                "Empty PDS host provided",
            ))?;
        }
        Ok(())
    }

    pub fn set_domain(&mut self, domain: String) -> SetupResult<()> {
        self.validate_domain(&domain)?;
        self.domain = Some(domain);
        Ok(())
    }

    pub fn set_pds_host(&mut self, pds_host: String) -> SetupResult<()> {
        self.validate_pds_host(&pds_host)?;
        if pds_host.contains("bsky.social") {
            return Err(SetupError::input(
                "bsky.social cannot be used as PDS",
                "Invalid PDS host",
            ))?;
        }
        self.pds_host = Some(pds_host);
        Ok(())
    }

    pub fn set_account_params(&mut self, params: AccountParams) -> SetupResult<()> {
        // Validate handle as a URL
        let handle_url = format!("https://{}", params.handle);
        Url::parse(&handle_url).map_err(|e| {
            SetupError::input(
                "Invalid handle format",
                format!("Handle must be a valid domain: {}", e),
            )
        })?;

        // Validate email format if provided
        if let Some(email) = &params.email {
            if !email.contains('@') || !email.contains('.') {
                return Err(SetupError::input(
                    "Invalid email format",
                    "Email must be in a valid format",
                )
                .into());
            }
        }

        self.account_params = Some(params);
        Ok(())
    }

    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    pub fn step_description(&self) -> &'static str {
        match self.current_step {
            SetupStep::Init => "Initializing setup process",
            SetupStep::Domain => "Configure your domain",
            SetupStep::Pds => "Configure your PDS host",
            SetupStep::Keys => "Generate keypair",
            SetupStep::DidDocument => "Create DID document",
            SetupStep::ServiceAuth => "Generate service authentication",
            SetupStep::Account => "Create and activate account",
            SetupStep::Complete => "Setup complete",
        }
    }

    pub fn step_help(&self) -> &'static str {
        match self.current_step {
            SetupStep::Init => "Starting the setup process...",
            SetupStep::Domain => "Enter your domain name (e.g., example.com)",
            SetupStep::Pds => "Enter your PDS host URL (e.g., https://pds.example.com)",
            SetupStep::Keys => "Generating secp256k1 keypair...",
            SetupStep::DidDocument => "Creating DID document with verification methods...",
            SetupStep::ServiceAuth => "Generating service authentication token...",
            SetupStep::Account => "Complete account setup with handle, password, and invite code",
            SetupStep::Complete => "Setup is complete. Your DID Web is ready to use.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_coordinator_initialization() {
        smol::block_on(async {
            let temp_dir = tempdir().unwrap();
            let mut coordinator = SetupCoordinator::new(temp_dir.path().to_path_buf());

            assert!(coordinator.initialize().await.is_ok());
            assert_eq!(coordinator.current_step(), SetupStep::Domain);
            assert!(temp_dir.path().exists());
        });
    }
}
