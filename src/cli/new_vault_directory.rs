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
use std::{fs, path::PathBuf};

use super::{ACCESS_CONTROL_DIRECTORY, KVSTORE_DIRECTORY};

#[derive(Debug, Parser)]
#[command(about = "Initialize the kubevault configuration")]
pub struct Command {
    #[arg(
        help = "Path to the directory where the kubevault configuration will be stored",
        env = "KUBEVAULT_DIR",
        default_value = "vault",
        value_name = "PATH",
        value_hint = clap::ValueHint::DirPath
    )]
    vault_dir: PathBuf,
}

impl Command {
    pub fn run(&self) -> Result<()> {
        let kvstore_dir = self.vault_dir.join(KVSTORE_DIRECTORY);
        if !kvstore_dir.exists() {
            fs::create_dir_all(&kvstore_dir).with_context(|| {
                format!(
                    "Failed to create the key-value store directory {:?}",
                    kvstore_dir
                )
            })?;
        }

        let access_control_dir = self.vault_dir.join(ACCESS_CONTROL_DIRECTORY);
        if !access_control_dir.exists() {
            fs::create_dir_all(&access_control_dir).with_context(|| {
                format!(
                    "Failed to create the access control directory {:?}",
                    access_control_dir
                )
            })?;
        }

        Ok(())
    }
}
