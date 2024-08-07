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
//!  `kubevault` is a tool to manage Kubernetes secrets and service accounts using a simple directory structure.
//! It is designed to be used with [chezmoi.sh](https://github.com/chezmoi-sh) to manage the vault directory.

mod cli;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let kubevault = cli::Opts::parse();

    kubevault.exec()
}
