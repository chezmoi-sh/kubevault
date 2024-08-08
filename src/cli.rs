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
**/

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};

mod can_read_secret;
mod external_secret_store;
mod generate_manifests;
mod new_vault_directory;

/// Access control directory name
pub const ACCESS_CONTROL_DIRECTORY: &str = "access_control";
/// Key-value store directory name
pub const KVSTORE_DIRECTORY: &str = "kvstore";

#[derive(Debug, Parser)]
#[command(
    name = "kubevault",
    about = "kubevault transforms a Kubernetes cluster into a secret management system.",
    long_about = "kubevault is a tool that transforms a Kubernetes cluster into a secret management system by relying on resources like Secrets and RBAC provided by Kubernetes.",
    author,
    version
)]
pub struct Opts {
    #[command(subcommand)]
    command: Option<KubeVaultCommands>,
}

#[derive(Debug, Subcommand)]
pub enum KubeVaultCommands {
    Generate(generate_manifests::Command),
    New(new_vault_directory::Command),
    CanRead(can_read_secret::Command),
    ExternalSecretStore(external_secret_store::Command),

    #[command(about = "Generate shell completion scripts")]
    Completion {
        #[arg(
            help = "The shell to generate the completion script for",
            value_parser = clap::value_parser!(Shell),
        )]
        shell: Shell,
    },
}

impl Opts {
    pub fn exec(&self) -> Result<()> {
        match &self.command {
            Some(KubeVaultCommands::Generate(cmd)) => cmd.run()?,
            Some(KubeVaultCommands::New(cmd)) => cmd.run()?,
            Some(KubeVaultCommands::CanRead(cmd)) => cmd.run()?,
            Some(KubeVaultCommands::ExternalSecretStore(cmd)) => cmd.run()?,

            Some(KubeVaultCommands::Completion { shell }) => match shell {
                Shell::Bash | Shell::Zsh | Shell::Fish | Shell::Elvish | Shell::PowerShell => {
                    let mut cmd = Opts::command();
                    generate(*shell, &mut cmd, "kubevault", &mut std::io::stdout());
                }
                _ => {
                    anyhow::bail!("Unsupported shell {:?}", shell);
                }
            },
            None => {
                anyhow::bail!("No subcommand provided. Use --help for more information.");
            }
        }

        Ok(())
    }
}
