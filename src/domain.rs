use crate::{context::SetupContext, errors::SetupResult};
use futures_lite::future::race;
use futures_util::FutureExt;
use smol::{future::Future, Timer};
use std::time::Duration;
use url::Url;

pub async fn validate_domain(domain: &str) -> SetupResult<()> {
    // Basic format validation
    if domain.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Domain cannot be empty",
        ))
        .with_domain_context("Invalid domain format")?;
    }

    // No protocol prefixes allowed
    if domain.contains("://") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Domain should not include protocol",
        ))
        .with_domain_context("Invalid domain format")?;
    }

    // Basic DNS validation
    if !domain.contains('.') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Domain must include at least one dot",
        ))
        .with_domain_context("Invalid domain format")?;
    }

    Ok(())
}

pub async fn validate_pds_host(pds_host: &str) -> SetupResult<()> {
    let url = Url::parse(pds_host)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid PDS URL: {}", e),
            )
        })
        .with_domain_context("Invalid PDS host format")?;

    if url.scheme() != "https" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "PDS host must use HTTPS",
        ))
        .with_domain_context("Invalid PDS protocol")?;
    }

    Ok(())
}

async fn with_timeout<F>(future: F, duration: Duration) -> SetupResult<surf::Response>
where
    F: Future<Output = Result<surf::Response, surf::Error>> + FutureExt,
{
    let request = future.map(|res| match res {
        Ok(response) => Ok(response),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Request failed: {}", e),
        )),
    });

    let timeout = async {
        Timer::after(duration).await;
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Request timed out",
        ))
    };

    race(request, timeout)
        .await
        .with_domain_context("PDS connection failed")
}

pub async fn check_pds_connection(pds_host: &str) -> SetupResult<()> {
    let url = format!("{}/xrpc/_health", pds_host.trim_end_matches('/'));

    let response = with_timeout(surf::get(url).send(), Duration::from_secs(10)).await?;

    if response.status() != 200 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("PDS returned status: {}", response.status()),
        ))
        .with_domain_context("PDS health check failed")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use smol::block_on;

    #[test]
    fn test_validate_domain() {
        block_on(async {
            // Valid domains
            assert!(validate_domain("example.com").await.is_ok());
            assert!(validate_domain("sub.example.com").await.is_ok());
            assert!(validate_domain("sub.sub.example.com").await.is_ok());

            // Invalid domains
            assert!(validate_domain("").await.is_err());
            assert!(validate_domain("https://example.com").await.is_err());
            assert!(validate_domain("noperiods").await.is_err());
        });
    }

    #[test]
    fn test_validate_pds_host() {
        block_on(async {
            // Valid PDS hosts
            assert!(validate_pds_host("https://pds.example.com").await.is_ok());
            assert!(validate_pds_host("https://pds.example.com/").await.is_ok());
            assert!(validate_pds_host("https://sub.pds.example.com")
                .await
                .is_ok());

            // Invalid PDS hosts
            assert!(validate_pds_host("http://pds.example.com").await.is_err());
            assert!(validate_pds_host("not-a-url").await.is_err());
            assert!(validate_pds_host("ftp://pds.example.com").await.is_err());
        });
    }

    #[test]
    fn test_check_pds_connection() {
        block_on(async {
            // Test with an invalid domain that should timeout or fail
            let result = check_pds_connection("https://invalid.example.com").await;
            assert!(result.is_err());

            // Test with a potentially valid PDS host
            let result = check_pds_connection("https://bsky.social").await;
            // We don't assert the result since it depends on external service
            println!("PDS connection test result: {:?}", result);
        });
    }
}
