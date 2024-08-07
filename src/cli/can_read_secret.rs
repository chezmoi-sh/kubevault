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

use anyhow::{Context, Result};
use clap::Parser;
use owo_colors::OwoColorize;
use std::{fs, path::PathBuf};
use walkdir::WalkDir;

use super::{ACCESS_CONTROL_DIRECTORY, KVSTORE_DIRECTORY};
use kubevault::{enforce_dns1035_format, get_access_control_list};

#[derive(Debug, Parser)]
#[command(about = "List all accessible secrets for a given user")]
pub struct Command {
    #[arg(
        help = "Path to the directory where the kubevault configuration is stored",
        long,
        env = "KUBEVAULT_DIR",
        default_value = "vault",
        value_name = "PATH",
        value_hint = clap::ValueHint::DirPath
    )]
    vault_dir: PathBuf,

    #[arg(help = "Only show secrets that the user is allowed to read", long)]
    show_only_allowed: bool,

    #[arg(
        help = "The user to list the secrets for",
        value_name = "USER",
        value_parser = clap::builder::NonEmptyStringValueParser::new(),
    )]
    user: String,
}

impl Command {
    pub fn run(&self) -> Result<()> {
        let user_file = self
            .vault_dir
            .join(ACCESS_CONTROL_DIRECTORY)
            .join(&self.user);
        if !user_file.exists() {
            anyhow::bail!(format!(
                "User {:?} does not exist (file {:?} not found)",
                self.user, user_file
            ));
        }

        let content = fs::read_to_string(&user_file).with_context(|| {
            format!(
                "Unable to read access control rules for {:?} on {:?}",
                self.user, &user_file
            )
        })?;
        let access_rules = content
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.trim().to_string())
            .collect::<Vec<_>>();

        let kvstore_dir = self.vault_dir.join(KVSTORE_DIRECTORY);
        let mut secrets: Vec<PathBuf> = Vec::new();
        for entry in WalkDir::new(&kvstore_dir) {
            let entry =
                entry.with_context(|| format!("Failed to read directory {:?}", &kvstore_dir))?;

            if entry.file_type().is_file() {
                secrets.push(
                    entry
                        .path()
                        .strip_prefix(&kvstore_dir)
                        .with_context(|| {
                            format!(
                                "Failed to strip prefix {:?} from {:?}",
                                &kvstore_dir,
                                entry.path()
                            )
                        })?
                        .to_owned(),
                );
            }
        }

        println!("List of secrets accessible by user '{}':", self.user);
        let allowed_secrets = get_access_control_list(&access_rules, &secrets);
        for (access, path) in allowed_secrets {
            if access {
                println!(
                    "● {}",
                    format!(
                        "{} ({:?})",
                        enforce_dns1035_format(path.to_str().unwrap())?,
                        path
                    )
                    .white()
                );
            } else if !self.show_only_allowed {
                println!(
                    "○ {}",
                    format!(
                        "{} ({:?})",
                        enforce_dns1035_format(path.to_str().unwrap())?,
                        path
                    )
                    .bright_black()
                    .strikethrough()
                );
            }
        }

        Ok(())
    }
}
