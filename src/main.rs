use reqwest::Client;
use serde::Deserialize;
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use tokio::sync::mpsc;

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
#[derive(Clone)]
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
            println!("Error accessing HIBP API: {}", e);
            return;
        }
    };

    // Build breach model vector, representing all breach domains.
    let breaches: Vec<Breach> = resp.json().await.unwrap();
    let domain_count = breaches.len();
    println!("Found {} breach domains!", domain_count);

    // Vec to hold JoinHandles for each domain check thread
    let mut handles = Vec::new();

    // Create a channel for passing results from the tasks to the main task
    let (tx, mut rx) = mpsc::channel(100);

    for breach in breaches {
        // Each task gets its own Sender
        let tx = tx.clone();

        // Spin up a task to check each domain
        let handle = tokio::task::spawn(async move {
            if !breach.domain.is_empty() {
                let client = Client::new();

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
                    Err(_e) => {
                        securitytxt_check.domain_error = true;
                        // Push compliance data to channel.
                        if let Err(_e) = tx.send(securitytxt_check).await {
                            println!("Failed to send result to main task");
                        }
                        return;
                    }
                };

                // Success?
                if !securitytxt_check.domain_error && securitytxt_resp.status().is_success() {
                    securitytxt_check.security_txt_exists = true;
                    securitytxt_check.security_txt_location = true;
                    securitytxt_check.security_txt_path =
                        format!("https://{}/.well-known/security.txt", breach.domain);
                } else {
                    // Check /security.txt
                    let securitytxt_resp2 = client
                        .get(format!("https://{}/security.txt", breach.domain))
                        .header("User-Agent", "HIBP_securitytxt")
                        .timeout(Duration::from_secs(5))
                        .send();

                    // Check for errors
                    let securitytxt_resp2 = match securitytxt_resp2.await {
                        Ok(securitytxt_resp2) => securitytxt_resp2,
                        Err(_e) => {
                            securitytxt_check.domain_error = true;
                            // Push compliance data to channel.
                            if let Err(_e) = tx.send(securitytxt_check).await {
                                println!("Failed to send result to main task");
                            }
                            return;
                        }
                    };

                    // Success?
                    if !securitytxt_check.domain_error && securitytxt_resp2.status().is_success() {
                        securitytxt_check.security_txt_exists = true;
                        securitytxt_check.security_txt_location = false;
                        securitytxt_check.security_txt_path =
                            format!("https://{}/security.txt", breach.domain);
                    } else {
                        securitytxt_check.security_txt_exists = false;
                        securitytxt_check.security_txt_location = false;
                    }
                }

                // Push compliance data to channel.
                if let Err(_e) = tx.send(securitytxt_check).await {
                    println!("Failed to send result to main task");
                }
            }
        });

        handles.push(handle);
    }

    // No more senders are being created, so we can drop this one
    drop(tx);

    // Vec to hold SecurityTxtChecks results from each domain check task
    let mut securitytxt_checks: Vec<SecurityTxtChecks> = Vec::new();

    // Receive SecurityTxtChecks results from the channel and push them into the vector
    while let Some(securitytxt_check) = rx.recv().await {
        securitytxt_checks.push(securitytxt_check);
    }

    // Wait for all threads to finish before generating report
    for handle in handles {
        handle.await.unwrap();
    }

    // Generate report :3
    // TODO: Output full report, report with only security.txt found, report with only security.txt not found?
    println!("Generating report...");
    let report_file = "Report.md";
    let mut file = File::create(report_file).unwrap();

    let mut report_header = "# HIBP Security.txt Compliance Report\n".to_string();
    report_header.push_str(&format!("**{} domains checked**\n\n", domain_count));
    report_header.push_str("## Summary of Results\n");
    report_header.push_str(
        "| **Domain** | **security.txt Found?** | **.well-known?** | **Observed Path** | **Errors** |\n",
    );
    report_header.push_str(
        "|:----------:|:-----------------------:|:----------------:|:-----------------:|:-----------------:|\n",
    );

    write!(&mut file, "{}", report_header).expect("Unable to write file");

    for breach_securitytxt in securitytxt_checks {
        let sec_txt_exists = if breach_securitytxt.security_txt_exists {
            ":white_check_mark:"
        } else {
            ":x:"
        };

        let sec_txt_location = if breach_securitytxt.security_txt_location {
            ":white_check_mark:"
        } else {
            ":x:"
        };

        let domain_error = if breach_securitytxt.domain_error {
            ":bangbang:"
        } else {
            " "
        };

        let report = format!(
            "| {} | {} | {} | {} | {} |\n",
            breach_securitytxt.domain,
            sec_txt_exists,
            sec_txt_location,
            breach_securitytxt.security_txt_path,
            domain_error
        );
        write!(&mut file, "{}", report).expect("Unable to write file");
    }
}
