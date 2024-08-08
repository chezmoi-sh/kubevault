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
use owo_colors::{OwoColorize, Stream, Style};
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
    pub fn run(&self, mut io_out: impl std::io::Write) -> Result<()> {
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

        writeln!(
            io_out,
            "List of secrets accessible by user '{}':",
            self.user
        )?;
        for (access, path) in get_access_control_list(&access_rules, &secrets) {
            if access {
                writeln!(
                    io_out,
                    "● {}",
                    format!(
                        "{} ({:?})",
                        enforce_dns1035_format(path.to_str().unwrap())?,
                        path
                    )
                    .if_supports_color(Stream::Stdout, |f| f.style(
                        if cfg!(test) {
                            Style::new()
                        } else {
                            Style::new().white()
                        }
                    ))
                )?;
            } else if !self.show_only_allowed {
                writeln!(
                    io_out,
                    "○ {}",
                    format!(
                        "{} ({:?})",
                        enforce_dns1035_format(path.to_str().unwrap())?,
                        path
                    )
                    .if_supports_color(Stream::Stdout, |f| f.style(
                        if cfg!(test) {
                            Style::new()
                        } else {
                            Style::new().bright_black().strikethrough()
                        }
                    ))
                )?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use similar_asserts::assert_eq;
    use std::{
        fs::File,
        io::{self, BufWriter, Write},
    };

    #[test]
    fn test_run_user_file_does_not_exist() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let user = "test";

        let command = Command {
            vault_dir: vault_dir.clone(),
            show_only_allowed: false,
            user: user.to_string(),
        };

        let result = command.run(io::stdout());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            format!(
                "User \"test\" does not exist (file {:?} not found)",
                vault_dir.join(ACCESS_CONTROL_DIRECTORY).join(user)
            )
        );
    }

    #[test]
    fn test_run_kvstore_dir_does_not_exist() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let user = "test";

        fs::create_dir_all(vault_dir.join(ACCESS_CONTROL_DIRECTORY))
            .expect("Failed to create directory for access control rules");
        File::create(vault_dir.join(ACCESS_CONTROL_DIRECTORY).join(user))
            .expect("Failed to create access control file");

        let command = Command {
            vault_dir: vault_dir.clone(),
            show_only_allowed: false,
            user: user.to_string(),
        };

        let result = command.run(io::stdout());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("Failed to read directory {:?}", vault_dir.join("kvstore"))
        );
    }

    #[test]
    fn test_run_no_access_rules() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let user = "test";

        fs::create_dir_all(vault_dir.join(ACCESS_CONTROL_DIRECTORY))
            .expect("Failed to create directory for access control rules");
        let mut user_file = File::create(vault_dir.join(ACCESS_CONTROL_DIRECTORY).join(user))
            .expect("Failed to create access control file");
        user_file
            .write_all(b"# No access rules")
            .expect("Failed to write access control rules");

        let kvstore_dir = vault_dir.join(KVSTORE_DIRECTORY);
        let secret_files = vec![
            "secret1",
            "secret2",
            "secret3",
            "dir1/secret1",
            "dir1/secret2",
            "dir1/secret3",
            "dir2/secret1",
            "dir2/secret3",
            "dir3/secret3",
        ];
        for secret_file in secret_files {
            fs::create_dir_all(kvstore_dir.join(secret_file).parent().unwrap())
                .expect("Failed to create directory for secrets");
            File::create(kvstore_dir.join(secret_file)).expect("Failed to create secret file");
        }

        let command = Command {
            vault_dir: vault_dir.clone(),
            show_only_allowed: false,
            user: user.to_string(),
        };

        let mut output = BufWriter::new(Vec::new());
        let result = command.run(&mut output);
        assert!(result.is_ok());
        let output = String::from_utf8(output.buffer().to_vec()).unwrap();

        #[cfg(not(windows))]
        assert_eq!(
            output,
            "List of secrets accessible by user 'test':
○ dir1-secret1 (\"dir1/secret1\")
○ dir1-secret2 (\"dir1/secret2\")
○ dir1-secret3 (\"dir1/secret3\")
○ dir2-secret1 (\"dir2/secret1\")
○ dir2-secret3 (\"dir2/secret3\")
○ dir3-secret3 (\"dir3/secret3\")
○ secret1 (\"secret1\")
○ secret2 (\"secret2\")
○ secret3 (\"secret3\")
"
        );
        #[cfg(windows)]
        assert_eq!(
            output,
            "List of secrets accessible by user 'test':
○ dir1-secret1 (\"dir1\\\\secret1\")
○ dir1-secret2 (\"dir1\\\\secret2\")
○ dir1-secret3 (\"dir1\\\\secret3\")
○ dir2-secret1 (\"dir2\\\\secret1\")
○ dir2-secret3 (\"dir2\\\\secret3\")
○ dir3-secret3 (\"dir3\\\\secret3\")
○ secret1 (\"secret1\")
○ secret2 (\"secret2\")
○ secret3 (\"secret3\")
"
        );
    }

    #[test]
    fn test_run_all_access_rules() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let user = "test";

        fs::create_dir_all(vault_dir.join(ACCESS_CONTROL_DIRECTORY))
            .expect("Failed to create directory for access control rules");
        let mut user_file = File::create(vault_dir.join(ACCESS_CONTROL_DIRECTORY).join(user))
            .expect("Failed to create access control file");
        user_file
            .write_all(b"# Access to all secrets\n**")
            .expect("Failed to write access control rules");

        let kvstore_dir = vault_dir.join(KVSTORE_DIRECTORY);
        let secret_files = vec![
            "secret1",
            "secret2",
            "secret3",
            "dir1/secret1",
            "dir1/secret2",
            "dir1/secret3",
            "dir2/secret1",
            "dir2/secret3",
            "dir3/secret3",
        ];
        for secret_file in secret_files {
            fs::create_dir_all(kvstore_dir.join(secret_file).parent().unwrap())
                .expect("Failed to create directory for secrets");
            File::create(kvstore_dir.join(secret_file)).expect("Failed to create secret file");
        }

        let command = Command {
            vault_dir: vault_dir.clone(),
            show_only_allowed: false,
            user: user.to_string(),
        };

        let mut output = BufWriter::new(Vec::new());
        let result = command.run(&mut output);
        assert!(result.is_ok());
        let output = String::from_utf8(output.buffer().to_vec()).unwrap();

        #[cfg(not(windows))]
        assert_eq!(
            output,
            "List of secrets accessible by user 'test':
● dir1-secret1 (\"dir1/secret1\")
● dir1-secret2 (\"dir1/secret2\")
● dir1-secret3 (\"dir1/secret3\")
● dir2-secret1 (\"dir2/secret1\")
● dir2-secret3 (\"dir2/secret3\")
● dir3-secret3 (\"dir3/secret3\")
● secret1 (\"secret1\")
● secret2 (\"secret2\")
● secret3 (\"secret3\")
"
        );
        #[cfg(windows)]
        assert_eq!(
            output,
            "List of secrets accessible by user 'test':
● dir1-secret1 (\"dir1\\\\secret1\")
● dir1-secret2 (\"dir1\\\\secret2\")
● dir1-secret3 (\"dir1\\\\secret3\")
● dir2-secret1 (\"dir2\\\\secret1\")
● dir2-secret3 (\"dir2\\\\secret3\")
● dir3-secret3 (\"dir3\\\\secret3\")
● secret1 (\"secret1\")
● secret2 (\"secret2\")
● secret3 (\"secret3\")
"
        );
    }

    #[test]
    fn test_run_show_mixed_access_rules() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let user = "test";

        fs::create_dir_all(vault_dir.join(ACCESS_CONTROL_DIRECTORY))
            .expect("Failed to create directory for access control rules");
        let mut user_file = File::create(vault_dir.join(ACCESS_CONTROL_DIRECTORY).join(user))
            .expect("Failed to create access control file");
        user_file
            .write_all(b"# Access to only some secrets\ndir1/*\ndir2/secret1\nsecret4\n*/*{1,2}\n!dir1/secret2")
            .expect("Failed to write access control rules");

        let kvstore_dir = vault_dir.join(KVSTORE_DIRECTORY);
        let secret_files = vec![
            "secret1",
            "secret2",
            "secret3",
            "dir1/secret1",
            "dir1/secret2",
            "dir1/secret3",
            "dir2/secret1",
            "dir2/secret3",
            "dir3/secret3",
        ];
        for secret_file in secret_files {
            fs::create_dir_all(kvstore_dir.join(secret_file).parent().unwrap())
                .expect("Failed to create directory for secrets");
            File::create(kvstore_dir.join(secret_file)).expect("Failed to create secret file");
        }

        let command = Command {
            vault_dir: vault_dir.clone(),
            show_only_allowed: false,
            user: user.to_string(),
        };

        let mut output = BufWriter::new(Vec::new());
        let result = command.run(&mut output);
        assert!(result.is_ok());
        let output = String::from_utf8(output.buffer().to_vec()).unwrap();

        #[cfg(not(windows))]
        assert_eq!(
            output,
            "List of secrets accessible by user 'test':
● dir1-secret1 (\"dir1/secret1\")
○ dir1-secret2 (\"dir1/secret2\")
● dir1-secret3 (\"dir1/secret3\")
● dir2-secret1 (\"dir2/secret1\")
○ dir2-secret3 (\"dir2/secret3\")
○ dir3-secret3 (\"dir3/secret3\")
○ secret1 (\"secret1\")
○ secret2 (\"secret2\")
○ secret3 (\"secret3\")
"
        );
        #[cfg(windows)]
        assert_eq!(
            output,
            "List of secrets accessible by user 'test':
● dir1-secret1 (\"dir1\\\\secret1\")
○ dir1-secret2 (\"dir1\\\\secret2\")
● dir1-secret3 (\"dir1\\\\secret3\")
● dir2-secret1 (\"dir2\\\\secret1\")
○ dir2-secret3 (\"dir2\\\\secret3\")
○ dir3-secret3 (\"dir3\\\\secret3\")
○ secret1 (\"secret1\")
○ secret2 (\"secret2\")
○ secret3 (\"secret3\")
"
        );
    }

    #[test]
    fn test_run_show_only_allowed() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let user = "test";

        fs::create_dir_all(vault_dir.join(ACCESS_CONTROL_DIRECTORY))
            .expect("Failed to create directory for access control rules");
        let mut user_file = File::create(vault_dir.join(ACCESS_CONTROL_DIRECTORY).join(user))
            .expect("Failed to create access control file");
        user_file
            .write_all(b"# Access to only some secrets\ndir1/*\ndir2/secret1\nsecret4\n*/*{1,2}\n!dir1/secret2")
            .expect("Failed to write access control rules");

        let kvstore_dir = vault_dir.join(KVSTORE_DIRECTORY);
        let secret_files = vec![
            "secret1",
            "secret2",
            "secret3",
            "dir1/secret1",
            "dir1/secret2",
            "dir1/secret3",
            "dir2/secret1",
            "dir2/secret3",
            "dir3/secret3",
        ];
        for secret_file in secret_files {
            fs::create_dir_all(kvstore_dir.join(secret_file).parent().unwrap())
                .expect("Failed to create directory for secrets");
            File::create(kvstore_dir.join(secret_file)).expect("Failed to create secret file");
        }

        let command = Command {
            vault_dir: vault_dir.clone(),
            show_only_allowed: true,
            user: user.to_string(),
        };

        let mut output = BufWriter::new(Vec::new());
        let result = command.run(&mut output);
        assert!(result.is_ok());
        let output = String::from_utf8(output.buffer().to_vec()).unwrap();

        #[cfg(not(windows))]
        assert_eq!(
            output,
            "List of secrets accessible by user 'test':
● dir1-secret1 (\"dir1/secret1\")
● dir1-secret3 (\"dir1/secret3\")
● dir2-secret1 (\"dir2/secret1\")
"
        );
        #[cfg(windows)]
        assert_eq!(
            output,
            "List of secrets accessible by user 'test':
● dir1-secret1 (\"dir1\\\\secret1\")
● dir1-secret3 (\"dir1\\\\secret3\")
● dir2-secret1 (\"dir2\\\\secret1\")
"
        );
    }
}
