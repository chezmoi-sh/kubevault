/*
 * Copyright (C) 2024 Alexandre Nicolaie (xunleii@users.noreply.github.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------------
*/

use std::{fs, io::Write, path};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use walkdir::WalkDir;

#[derive(Debug, Parser)]
#[command(
    name = "kubevault",
    about = "kubevault transforms a Kubernetes cluster into a secret management system.",
    long_about = "kubevault is a tool that transforms a Kubernetes cluster into a secret management system by relying on resources like Secrets and RBAC provided by Kubernetes.",
    author,
    version
)]
struct Opts {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Generate all Kubernetes manifests")]
    Generate {
        #[arg(
            help = "Namespace where the kvstore will be created",
            long,
            short = 'n',
            env = "KUBEVAULT_NAMESPACE",
            default_value = "kubevault-kvstore",
            value_name = "NAMESPACE",
            value_parser = clap::builder::NonEmptyStringValueParser::new()
        )]
        namespace: String,

        #[arg(
            help = "Output directory where all manifests will be generated",
            long,
            env = "KUBEVAULT_OUTPUT_DIR",
            value_name = "PATH",
            value_hint = clap::ValueHint::DirPath
        )]
        output_dir: Option<path::PathBuf>,

        #[arg(
            help = "Path to the directory where the kubevault configuration is stored",
            long,
            env = "KUBEVAULT_DIR",
            default_value = "vault",
            value_name = "PATH",
            value_hint = clap::ValueHint::DirPath
        )]
        vault_dir: kubevault::VaultDir,
    },

    #[command(about = "Initialize the kubevault configuration")]
    New {
        #[arg(
            help = "Path to the directory where the kubevault configuration will be stored",
            env = "KUBEVAULT_DIR",
            default_value = "vault",
            value_name = "PATH",
            value_hint = clap::ValueHint::DirPath
        )]
        vault_dir: kubevault::VaultDir,
    },

    #[command(about = "Generate shell completion scripts")]
    Completion {
        #[arg(
            help = "The shell to generate the completion script for",
            value_parser = clap::value_parser!(Shell),
        )]
        shell: Shell,
    },
}

fn main() -> Result<()> {
    let opts: Opts = Opts::parse();

    match opts.command {
        Some(Commands::Generate {
            namespace,
            output_dir,
            vault_dir,
        }) => generate_manifests(vault_dir, namespace, output_dir)?,
        Some(Commands::New { vault_dir }) => init_vault(vault_dir)?,
        Some(Commands::Completion { shell }) => match shell {
            Shell::Bash | Shell::Zsh | Shell::Fish | Shell::Elvish | Shell::PowerShell => {
                let mut cmd = Opts::command();
                generate(shell, &mut cmd, "kubevault", &mut std::io::stdout());
            }
            _ => {
                Err(anyhow::anyhow!("Unsupported shell {:?}", shell))?;
            }
        },
        None => {
            Err(anyhow::anyhow!(
                "No subcommand provided. Use --help for more information."
            ))?;
        }
    }

    Ok(())
}

/// Generate all manifest based on the vault directory
fn generate_manifests(
    vault_dir: kubevault::VaultDir,
    namespace: String,
    output_dir: Option<path::PathBuf>,
) -> Result<()> {
    let secrets = WalkDir::new(vault_dir.kvstore_directory())
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_owned())
        .collect::<Vec<_>>();
    let users = WalkDir::new(vault_dir.access_control_directory())
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_owned())
        .collect::<Vec<_>>();

    let secret_manifests =
        kubevault::generate_secret_manifests(vault_dir.clone(), &namespace, secrets.clone())?;
    let rbac_manifests = kubevault::generate_rbac(vault_dir, &namespace, users, secrets)?;

    match output_dir {
        Some(dir) => {
            for secret in secret_manifests {
                let path = dir.join(format!(
                    "secret-{}.yaml",
                    secret.metadata.name.as_ref().unwrap()
                ));
                let file = fs::File::create(&path)
                    .with_context(|| format!("Failed to create manifest {:?}", &path))?;
                serde_yaml::to_writer(file, &secret.clone())?;
            }

            for (sa, secret, role, binding) in rbac_manifests {
                let path = dir.join(format!(
                    "access-control-{}.yaml",
                    sa.metadata.name.as_ref().unwrap()
                ));
                let mut file = fs::File::create(&path)
                    .with_context(|| format!("Failed to create manifest {:?}", &path))?;

                serde_yaml::to_writer(&file, &sa).with_context(|| {
                    format!("Failed to write access control manifests {:?}", &path)
                })?;
                file.write("---\n".as_bytes())?;
                serde_yaml::to_writer(&file, &secret).with_context(|| {
                    format!("Failed to write access control manifests {:?}", &path)
                })?;
                file.write("---\n".as_bytes())?;
                serde_yaml::to_writer(&file, &role).with_context(|| {
                    format!("Failed to write access control manifests {:?}", &path)
                })?;
                file.write("---\n".as_bytes())?;
                serde_yaml::to_writer(&file, &binding).with_context(|| {
                    format!("Failed to write access control manifests {:?}", &path)
                })?;
            }
        }
        None => {
            for secret in secret_manifests {
                println!("---");
                print!("{}", serde_yaml::to_string(&secret)?);
            }

            for (sa, secret, role, binding) in rbac_manifests.iter() {
                println!("---");
                print!("{}", serde_yaml::to_string(sa)?);
                println!("---");
                print!("{}", serde_yaml::to_string(secret)?);
                println!("---");
                print!("{}", serde_yaml::to_string(role)?);
                println!("---");
                print!("{}", serde_yaml::to_string(binding)?);
            }
        }
    }
    Ok(())
}

/// Create the vault directory with the necessary subdirectories
fn init_vault(vault_dir: kubevault::VaultDir) -> Result<()> {
    let kvstore_dir = vault_dir.kvstore_directory();
    let access_control_dir = vault_dir.access_control_directory();

    if !kvstore_dir.exists() {
        std::fs::create_dir_all(vault_dir.kvstore_directory()).with_context(|| {
            format!(
                "Failed to create the key-value store directory {:?}",
                kvstore_dir
            )
        })?;
    }

    if !access_control_dir.exists() {
        std::fs::create_dir_all(vault_dir.access_control_directory()).with_context(|| {
            format!(
                "Failed to create the access control directory {:?}",
                access_control_dir
            )
        })?;
    }

    Ok(())
}
