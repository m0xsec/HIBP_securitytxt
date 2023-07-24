use reqwest::Client;
use serde::Deserialize;
use std::fs::{self, File};
use std::io::Write;
use std::time::Duration;

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

    /// Was there an error contacting the domain?
    domain_error: bool,

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
        .timeout(Duration::from_secs(5))
        .send();

    // Check for errors
    let resp = match resp.await {
        Ok(resp) => resp,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    // Build breach model vector, representing all breach domains.
    let breaches: Vec<Breach> = resp.json().await.unwrap();
    let domain_count = breaches.len();
    println!("Found {} breach domains!", domain_count);

    // Build security.txt compliance report data  for each domain.
    let mut securitytxt_checks: Vec<SecurityTxtChecks> = Vec::new();
    for breach in breaches {
        if !breach.domain.is_empty() {
            println!("Running checks on {} ...", breach.domain);
            let mut securitytxt_check = SecurityTxtChecks {
                domain: breach.domain.clone(),
                domain_error: false,
                security_txt_path: "".to_string(),
                security_txt_exists: false,
                security_txt_location: false,
            };

            // Check .well-known/security.txt
            let securitytxt_resp = client
                .get(format!(
                    "https://{}/.well-known/security.txt",
                    breach.domain
                ))
                .header("User-Agent", "HIBP_securitytxt")
                .timeout(Duration::from_secs(5))
                .send();

            // Check for errors
            let securitytxt_resp = match securitytxt_resp.await {
                Ok(securitytxt_resp) => securitytxt_resp,
                Err(e) => {
                    //println!("Error: {}", e);
                    securitytxt_check.domain_error = true;
                    securitytxt_checks.push(securitytxt_check);
                    continue;
                }
            };

            // Success?
            if securitytxt_resp.status().is_success() {
                /*println!(
                    "Found security.txt at {}/.well-known/security.txt",
                    breach.domain
                );*/
                securitytxt_check.security_txt_exists = true;
                securitytxt_check.security_txt_location = true;
                securitytxt_check.security_txt_path =
                    format!("https://{}/.well-known/security.txt", breach.domain);
            } else {
                /*println!(
                    "No security.txt found at {}/.well-known/security.txt",
                    breach.domain
                );*/

                // Check .well-known/security.txt
                let securitytxt_resp2 = client
                    .get(format!("https://{}/security.txt", breach.domain))
                    .header("User-Agent", "HIBP_securitytxt")
                    .timeout(Duration::from_secs(5))
                    .send();

                // Check for errors
                let securitytxt_resp2 = match securitytxt_resp2.await {
                    Ok(securitytxt_resp2) => securitytxt_resp2,
                    Err(e) => {
                        //println!("Error: {}", e);
                        securitytxt_check.domain_error = true;
                        securitytxt_checks.push(securitytxt_check);
                        continue;
                    }
                };

                // Success?
                if securitytxt_resp2.status().is_success() {
                    //println!("Found security.txt at {}/security.txt", breach.domain);
                    securitytxt_check.security_txt_exists = true;
                    securitytxt_check.security_txt_location = false;
                    securitytxt_check.security_txt_path =
                        format!("https://{}/security.txt", breach.domain);
                } else {
                    //println!("No security.txt found at {}/security.txt", breach.domain);
                    securitytxt_check.security_txt_exists = false;
                    securitytxt_check.security_txt_location = false;
                }
            }

            // Push compliance data to vector.
            securitytxt_checks.push(securitytxt_check);
        }
    }

    // TODO: Generate report :3
    println!("Generating report...");
    let report_file = "Report.md";
    let mut file = File::create(report_file).unwrap();

    let mut report_header = "# HIBP Security.txt Compliance Report\n".to_string();
    report_header.push_str(&format!("**{} domains checked**\n\n", domain_count));
    report_header.push_str("## Summary of Results\n");
    report_header.push_str(
        "| **Domain** | **security.txt Found?** | **.well-known?** | **Observed Path** |\n",
    );
    report_header.push_str(
        "|:----------:|:-----------------------:|:----------------:|:-----------------:|\n",
    );

    writeln!(&mut file, "{}", report_header).expect("Unable to write file");

    for breach_securitytxt in securitytxt_checks {
        let report = format!(
            "| {} | {} | {} | {} |\n",
            breach_securitytxt.domain,
            breach_securitytxt.security_txt_exists,
            breach_securitytxt.security_txt_location,
            breach_securitytxt.security_txt_path
        );
        writeln!(&mut file, "{}", report).expect("Unable to write file");
    }
}
