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

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    // Pull the breach model for all breach domains from HIBP
    let client = Client::new();
    let url = "https://haveibeenpwned.com/api/v3/breaches";

    let resp = client
        .get(url)
        .header("User-Agent", "HIBP_securitytxt")
        .send();

    let breaches: Vec<Breach> = resp.await.unwrap().json().await.unwrap();

    // Pull all of the domains from the breach models
    for breach in breaches {
        if !breach.domain.is_empty() {
            println!("Domain: {}", breach.domain);
        }
    }

    // TODO: Kick off requests to check security.txt files for each domain
    // Check domain.com/security.txt and domain.com/.well-known/security.txt
    // Any other paths to check?
}
