use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

/// HIBP Breach Model
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Breach {
    name: String,
    title: String,
    domain: String,
    breach_date: String,
    added_date: String,
    modified_date: String,
    pwn_count: i32,
    description: String,
    logo_path: String,
    data_classes: Vec<String>,
    is_verified: bool,
    is_fabricated: bool,
    is_sensitive: bool,
    is_retired: bool,
    is_spam_list: bool,
}

/// RFC 9116 Compliance Checks
/// https://securitytxt.org/
/// https://www.rfc-editor.org/rfc/rfc9116
/// Represents some simple checks to report notable issues with security.txt files.
struct SecurityTxtChecks {
    /// Domain being checked.
    domain: String,

    /// Path to the security.txt file, if found.
    security_txt_path: String,

    /// Is the file present?
    security_txt_exists: bool,

    /// Is the file in the correct location?
    security_txt_location: bool,
    // TODO: Add more checks...
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    // Pull the breach model for all breach domains from HIBP
    let client = Client::new();
    let url = "https://haveibeenpwned.com/api/v3/breaches";

    let resp = client
        .get(url)
        .header("User-Agent", "HIBP_securitytxt")
        .timeout(Duration::from_secs(30))
        .send();

    // Check for timeout error
    let resp = match resp.await {
        Ok(resp) => resp,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    let breaches: Vec<Breach> = resp.json().await.unwrap();

    println!("Found {} breach domains!", breaches.len());

    // Pull all of the domains from the breach models
    for breach in breaches {
        if !breach.domain.is_empty() {
            println!("Running checks on {} ...", breach.domain);

            // Check .well-known/security.txt
            let securitytxt_resp = client
                .get(format!(
                    "https://{}/.well-known/security.txt",
                    breach.domain
                ))
                .header("User-Agent", "HIBP_securitytxt")
                .timeout(Duration::from_secs(30))
                .send();

            // Check for timeout error
            let securitytxt_resp = match securitytxt_resp.await {
                Ok(securitytxt_resp) => securitytxt_resp,
                Err(e) => {
                    println!("Error: {}", e);
                    continue;
                }
            };

            // Success?
            if securitytxt_resp.status().is_success() {
                println!(
                    "Found security.txt at {}/.well-known/security.txt",
                    breach.domain
                );
            } else {
                println!(
                    "No security.txt found at {}/.well-known/security.txt",
                    breach.domain
                );

                // Check .well-known/security.txt
                let securitytxt_resp2 = client
                    .get(format!("https://{}/security.txt", breach.domain))
                    .header("User-Agent", "HIBP_securitytxt")
                    .timeout(Duration::from_secs(30))
                    .send();

                // Check for timeout error
                let securitytxt_resp2 = match securitytxt_resp2.await {
                    Ok(securitytxt_resp2) => securitytxt_resp2,
                    Err(e) => {
                        println!("Error: {}", e);
                        continue;
                    }
                };

                // Success?
                if securitytxt_resp2.status().is_success() {
                    println!("Found security.txt at {}/security.txt", breach.domain);
                } else {
                    println!("No security.txt found at {}/security.txt", breach.domain);
                }
            }
        }
    }

    // TODO: Kick off requests to check security.txt files for each domain
    // Check domain.com/security.txt and domain.com/.well-known/security.txt
    // Any other paths to check?
}
