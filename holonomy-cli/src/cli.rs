// @trace TASK-114
// @trace TASK-005
// @trace TASK-072
// @trace TASK-021
// @trace TASK-043
// @trace TASK-045
// @trace TASK-046
// @trace TASK-051
// @trace TASK-048
// @trace TASK-049
// @trace TASK-079
// @trace TASK-085
// Command Line Interface for Holonomy

use crate::formatter::{extract_columns, format_ascii_table};
use clap::{Parser, Subcommand};
use holonomy_core::policy::manifest::{
    EncryptionBlock, PolicyEnvelope, PolicyManifest, PrincipalPolicy,
};
use holonomy_core::policy::signer::{get_public_key_hex, sign_manifest, verify_manifest};
use holonomy_core::schema::drift::{
    check_drift_for_uris, check_local_directory_drift, get_first_parquet_file,
};
use holonomy_core::schema::footer::fetch_parquet_metadata;
use holonomy_core::schema::s3_list::list_s3_objects;
use std::collections::HashMap;
use std::fs;
use std::process;

#[derive(Parser)]
#[command(name = "holonomy")]
#[command(bin_name = "holonomy")]
#[command(about = "Command Line Interface for Holonomy", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum AuthCommands {
    /// Authenticate via OIDC Device Authorization Flow and save credentials
    Login,
    /// Remove cached credentials
    Logout,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Authentication commands
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// Cryptographically signs a Policy Manifest JSON file using an Ed25519 Private Key
    Sign {
        /// Path to the JSON policy manifest to be signed
        manifest_path: String,
        /// Optional: The 32-byte Ed25519 private key in hex format. If omitted, a secure random key will be generated.
        #[arg(short = 'k', long = "key")]
        private_key_hex: Option<String>,
        /// Optional: Output path for the signed PolicyEnvelope. Defaults to "holonomy_master_policy.json".
        #[arg(short = 'o', long = "out")]
        output_path: Option<String>,
    },
    /// Verifies the Ed25519 signature of a Policy Manifest
    Verify {
        /// Path to the JSON policy manifest (or PolicyEnvelope) to verify
        manifest_path: String,
        /// The 32-byte Ed25519 public key in hex format
        public_key_hex: String,
        /// Optional: The hex-encoded signature (required if verifying a bare manifest payload)
        #[arg(short = 's', long = "signature")]
        signature_hex: Option<String>,
    },
    /// Inspects the schema of a Parquet dataset without downloading row-level data
    Inspect {
        /// Target URI for inspection (e.g., local path or s3://...)
        target_uri: String,

        /// Generate a baseline policy JSON instead of an ASCII table
        #[arg(short = 'g', long = "generate-contract")]
        generate_contract: bool,

        /// Write the generated policy JSON to the specified file
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },
    /// Manage master policies
    Policy {
        /// Generate a dummy signed policy for testing
        #[arg(long = "create-dummy")]
        create_dummy: bool,

        /// Generate an unsigned policy template (payload only)
        #[arg(long = "create-template")]
        create_template: bool,

        /// Write the generated policy JSON to the specified file
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },
}

fn read_manifest_and_key(manifest_path: &str, key_hex: &str) -> Result<(String, [u8; 32]), String> {
    let manifest_content = fs::read_to_string(manifest_path)
        .map_err(|e| format!("Failed to read manifest file '{}': {}", manifest_path, e))?;

    let key_bytes =
        hex::decode(key_hex).map_err(|e| format!("Invalid hex format for key: {}", e))?;

    if key_bytes.len() != 32 {
        return Err(format!(
            "Invalid key length: expected 32 bytes, got {}",
            key_bytes.len()
        ));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);

    Ok((manifest_content, key_array))
}

pub async fn run_cli_with_args<I, T>(args: I)
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let _ = dotenvy::dotenv();
    let cli = Cli::parse_from(args);

    match cli.command {
        Commands::Auth { command } => match command {
            AuthCommands::Login => {
                if let Err(e) = crate::cmd_auth::perform_login().await {
                    eprintln!("Auth Error: {}", e);
                    process::exit(1);
                }
            }
            AuthCommands::Logout => {
                if let Err(e) = crate::cmd_auth::perform_logout() {
                    eprintln!("Logout Error: {}", e);
                    process::exit(1);
                }
            }
        },
        Commands::Sign {
            manifest_path,
            private_key_hex,
            output_path,
        } => {
            let manifest_content = std::fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
                eprintln!("Failed to read manifest file: {}", e);
                process::exit(1);
            });

            let (key_array, is_generated) = match private_key_hex {
                Some(hex_str) => {
                    let bytes = hex::decode(hex_str).unwrap_or_else(|_| {
                        eprintln!("Error: Invalid hex string for private key.");
                        process::exit(1);
                    });
                    if bytes.len() != 32 {
                        eprintln!(
                            "Error: Private key must be exactly 32 bytes (64 hex characters)."
                        );
                        process::exit(1);
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    (arr, false)
                }
                None => {
                    use rand_core::{OsRng, RngCore};
                    let mut arr = [0u8; 32];
                    OsRng.fill_bytes(&mut arr);
                    (arr, true)
                }
            };

            let signature = sign_manifest(&manifest_content, &key_array).unwrap_or_else(|e| {
                eprintln!("Failed to sign manifest: {:?}", e);
                process::exit(1);
            });

            let public_key_hex = get_public_key_hex(&key_array);

            let envelope = PolicyEnvelope {
                signature: signature.clone(),
                payload: manifest_content,
            };

            let out_json = serde_json::to_string_pretty(&envelope).unwrap();
            let out_path = output_path.unwrap_or_else(|| "holonomy_master_policy.json".to_string());

            if let Err(e) = std::fs::write(&out_path, out_json) {
                eprintln!("Failed to write signed envelope: {}", e);
                process::exit(1);
            }

            if is_generated {
                println!("Generated new secure Ed25519 key pair.");
                println!("Private Key (keep secret!): {}", hex::encode(key_array));
            }
            println!("Public Key (HOLONOMY_POLICY_KEY): {}", public_key_hex);
            println!("Signature: {}", signature);
            println!("Successfully created signed envelope at: {}", out_path);
        }
        Commands::Verify {
            manifest_path,
            public_key_hex,
            signature_hex,
        } => {
            let (file_content, key_array) =
                match read_manifest_and_key(&manifest_path, &public_key_hex) {
                    Ok(res) => res,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        process::exit(1);
                    }
                };

            let (payload_to_verify, sig_to_verify) = if let Ok(envelope) =
                serde_json::from_str::<PolicyEnvelope>(&file_content)
            {
                let sig = signature_hex.unwrap_or(envelope.signature);
                (envelope.payload, sig)
            } else {
                let sig = match signature_hex {
                    Some(s) => s,
                    None => {
                        eprintln!(
                            "Error: Provided file is not a PolicyEnvelope. You must provide --signature to verify a raw manifest."
                        );
                        process::exit(1);
                    }
                };
                (file_content, sig)
            };

            match verify_manifest(&payload_to_verify, &sig_to_verify, &key_array) {
                Ok(_) => {
                    println!("Signature valid");
                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("Signature invalid: {:?}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Policy {
            create_dummy,
            create_template,
            output,
        } => {
            if create_dummy || create_template {
                let mut principals = HashMap::new();
                let mut column_masks = HashMap::new();
                column_masks.insert("salary".to_string(), "REDACT".to_string());
                let mut tag_masks = HashMap::new();
                tag_masks.insert("pii".to_string(), "REDACT".to_string());
                principals.insert(
                    "analyst".to_string(),
                    PrincipalPolicy {
                        global_row_filters: vec!["department = 'sales'".to_string()],
                        selective_row_filters: vec![],
                        column_masks,
                        tag_masks,
                        sampling_cap: Some(1000),
                    },
                );

                let manifest = PolicyManifest {
                    version: "1.0".to_string(),
                    principals,
                    encryption: Some(EncryptionBlock {
                        required_tags: vec![
                            "pii".to_string(),
                            "pci".to_string(),
                            "phi".to_string(),
                        ],
                        required_columns: vec![
                            "ssn".to_string(),
                            "password".to_string(),
                            "secret".to_string(),
                            "salary".to_string(),
                            "credit_card".to_string(),
                            "dob".to_string(),
                            "email".to_string(),
                            "phone".to_string(),
                        ],
                    }),
                    purpose_bindings: Some({
                        let mut pb = std::collections::HashMap::new();
                        pb.insert("marketing_campaign".to_string(), "analyst".to_string());
                        pb
                    }),
                };

                let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();

                let out_content = if create_template {
                    manifest_json
                } else {
                    let dummy_key = [1u8; 32];
                    let signature = sign_manifest(&manifest_json, &dummy_key).unwrap();
                    let public_key_hex = get_public_key_hex(&dummy_key);

                    let envelope = PolicyEnvelope {
                        signature,
                        payload: manifest_json,
                    };

                    let envelope_json = serde_json::to_string_pretty(&envelope).unwrap();

                    eprintln!("============================================================");
                    eprintln!("Dummy Policy Generated!");
                    eprintln!("Verifying Public Key (Hex): {}", public_key_hex);
                    eprintln!("You can use this key with 'holonomy verify --public-key-hex'");
                    eprintln!("============================================================");

                    envelope_json
                };

                if let Some(out_file) = output {
                    if let Err(e) = std::fs::write(&out_file, &out_content) {
                        eprintln!("Error writing policy to file: {}", e);
                        process::exit(1);
                    } else {
                        println!("Policy successfully written to {}", out_file);
                    }
                } else {
                    println!("{}", out_content);
                }
            } else {
                eprintln!("Error: specify an action like --create-dummy or --create-template");
                process::exit(1);
            }
        }
        Commands::Inspect {
            target_uri,
            generate_contract,
            output,
        } => {
            let mut target = target_uri.clone();
            let reqwest_client = reqwest::Client::new();
            let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
                .force_path_style(true)
                .build();
            let s3_client = aws_sdk_s3::Client::from_conf(s3_config);

            if !target.starts_with("http")
                && !target.starts_with("s3://")
                && !target.starts_with("r2://")
            {
                if let Ok(metadata) = std::fs::metadata(&target)
                    && metadata.is_dir()
                {
                    let _ = check_local_directory_drift(&target).await;
                    if let Some(first_file) = get_first_parquet_file(&target) {
                        target = first_file;
                    } else {
                        eprintln!("Error: No parquet files found in directory");
                        process::exit(1);
                    }
                }
            } else if (target.starts_with("s3://") || target.starts_with("r2://"))
                && !target.ends_with(".parquet")
                && let Ok(uris) = list_s3_objects(&reqwest_client, &target, 51, None).await
            {
                let drift_detected = check_drift_for_uris(&uris).await.unwrap_or(false);
                if drift_detected {
                    eprintln!(
                        "WARNING: Structural mutations (schema drift) detected within remote directory {}",
                        target
                    );
                }
                if !uris.is_empty() {
                    target = uris[0].clone();
                } else {
                    eprintln!("Error: No parquet files found in remote directory");
                    process::exit(1);
                }
            }

            match fetch_parquet_metadata(Some(&s3_client), Some(&reqwest_client), &target).await {
                Ok(metadata) => {
                    let columns = extract_columns(&metadata);

                    if generate_contract {
                        use crate::contract_gen::generate_contract;
                        let policy_json = generate_contract(&target_uri, &columns);

                        if let Some(out_file) = output {
                            if let Err(e) = std::fs::write(&out_file, &policy_json) {
                                eprintln!("Error writing policy to file: {}", e);
                                process::exit(1);
                            } else {
                                println!("Policy successfully written to {}", out_file);
                            }
                        } else {
                            println!("{}", policy_json);
                        }
                    } else {
                        let table = format_ascii_table(&columns);
                        println!("{}", table);
                    }
                }
                Err(e) => {
                    eprintln!("Error inspecting schema: {:?}", e);
                    process::exit(1);
                }
            }
        }
    }
}
