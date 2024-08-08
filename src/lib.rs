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
//!
//! This library provides the core functionalities to generate Kubernetes manifests from the vault directory:
//! - Generate the Secret manifests from the kvstore directory (`generate_secret_manifests`)
//! - Generate the RBAC manifests for all the accounts in the access control directory (`generate_rbac_manifests`)
//! - Generate the list of secrets that are accessible by the given access rules (`get_access_control_list`)
//! - Enforce DNS1035 format for a string (`enforce_dns1035_format`)

use anyhow::{Ok, Result};
use glob_match::glob_match;
use lazy_static::lazy_static;
use regex::Regex;
use std::path::PathBuf;

/// Generate the list of secrets that are accessible by the given access rules
pub fn get_access_control_list(
    access_rules: &[String],
    secrets: &[PathBuf],
) -> Vec<(bool, PathBuf)> {
    let mut allowed_secrets = secrets
        .iter()
        .map(|path| (false, path.to_owned()))
        .collect::<Vec<_>>();

    for rule in access_rules {
        allowed_secrets.iter_mut().for_each(|(access, path)| {
            if !rule.starts_with('!') {
                *access = glob_match(rule, path.to_str().unwrap()) || *access;
            } else {
                *access = !glob_match(&rule[1..], path.to_str().unwrap()) && *access;
            }
        });
    }

    allowed_secrets.sort_by(|(_, lhs), (_, rhs)| lhs.cmp(rhs));
    allowed_secrets
}

lazy_static! {
    static ref RX_INVALID_DNS1035_HEAD: Regex = Regex::new(r"^[a-z]").unwrap();
    static ref RX_INVALID_DNS1035_CHAR: Regex = Regex::new(r"[^-a-z0-9]").unwrap();
    static ref RX_INVALID_DNS1035_TAIL: Regex = Regex::new(r"[a-z0-9]$").unwrap();
}

/// Enforce DNS1035 format for a string
pub fn enforce_dns1035_format(name: &str) -> Result<String> {
    let mut name = name.to_lowercase();

    if !RX_INVALID_DNS1035_HEAD.is_match(&name) || !RX_INVALID_DNS1035_TAIL.is_match(&name) {
        anyhow::bail!(
            "Invalid DNS1035 name {:?}: must validate '^[a-z][a-z0-9-]*[a-z0-9]$",
            name
        );
    } else if RX_INVALID_DNS1035_CHAR.is_match(&name) {
        name = RX_INVALID_DNS1035_CHAR.replace_all(&name, "-").to_string();
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enforce_dns1035_format_valid_name() {
        let name = "valid-name";
        let result = enforce_dns1035_format(name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), name);
    }

    #[test]
    fn test_enforce_dns1035_format_invalid_head() {
        let name = "1nvalid-name";
        let result = enforce_dns1035_format(name);
        assert!(result.is_err());
    }

    #[test]
    fn test_enforce_dns1035_format_invalid_tail() {
        let name = "invalid-name-";
        let result = enforce_dns1035_format(name);
        assert!(result.is_err());
    }

    #[test]
    fn test_enforce_dns1035_format_lowercase() {
        let name = "UPPERCASE";
        let result = enforce_dns1035_format(name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "uppercase");
    }

    #[test]
    fn test_enforce_dns1035_format_name_with_special_characters() {
        let name = "name_with#special!characters";
        let result = enforce_dns1035_format(name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "name-with-special-characters");
    }

    #[test]
    fn test_list_accessible_secret_simple() {
        let access_rules = vec![
            "{y,z}/*".to_string(),
            "a/**".to_string(),
            "!a/b/c/**".to_string(),
            "**/*{b,c}/file-b".to_string(),
            "!z/folder-b/file-b".to_string(),
        ];
        let secrets = vec![
            PathBuf::from("x/file-a"),
            PathBuf::from("x/file-b"),
            PathBuf::from("y/file-a"),
            PathBuf::from("y/file-b"),
            PathBuf::from("z/file-a"),
            PathBuf::from("z/folder-a/file-a"),
            PathBuf::from("z/folder-b/file-a"),
            PathBuf::from("z/folder-b/file-b"),
            PathBuf::from("a/b/c/file-a"),
            PathBuf::from("a/b/c/file-b"),
            PathBuf::from("a/b/d/file-a"),
            PathBuf::from("a/b/d/file-b"),
        ];

        assert_eq!(
            get_access_control_list(&access_rules, &secrets),
            vec![
                (false, PathBuf::from("a/b/c/file-a")),
                (true, PathBuf::from("a/b/c/file-b")),
                (true, PathBuf::from("a/b/d/file-a")),
                (true, PathBuf::from("a/b/d/file-b")),
                (false, PathBuf::from("x/file-a")),
                (false, PathBuf::from("x/file-b")),
                (true, PathBuf::from("y/file-a")),
                (true, PathBuf::from("y/file-b")),
                (true, PathBuf::from("z/file-a")),
                (false, PathBuf::from("z/folder-a/file-a")),
                (false, PathBuf::from("z/folder-b/file-a")),
                (false, PathBuf::from("z/folder-b/file-b")),
            ]
        );
    }

    #[test]
    fn test_list_accessible_secret_shuffled() {
        let access_rules = vec![
            "a/**".to_string(),
            "!z/folder-b/file-b".to_string(),
            "{y,z}/*".to_string(),
            "**/*{b,c}/file-b".to_string(),
            "!a/b/c/**".to_string(),
        ];
        let secrets = vec![
            PathBuf::from("x/file-a"),
            PathBuf::from("x/file-b"),
            PathBuf::from("y/file-a"),
            PathBuf::from("y/file-b"),
            PathBuf::from("z/file-a"),
            PathBuf::from("z/folder-a/file-a"),
            PathBuf::from("z/folder-b/file-a"),
            PathBuf::from("z/folder-b/file-b"),
            PathBuf::from("a/b/c/file-a"),
            PathBuf::from("a/b/c/file-b"),
            PathBuf::from("a/b/d/file-a"),
            PathBuf::from("a/b/d/file-b"),
        ];

        assert_eq!(
            get_access_control_list(&access_rules, &secrets),
            vec![
                (false, PathBuf::from("a/b/c/file-a")),
                (false, PathBuf::from("a/b/c/file-b")),
                (true, PathBuf::from("a/b/d/file-a")),
                (true, PathBuf::from("a/b/d/file-b")),
                (false, PathBuf::from("x/file-a")),
                (false, PathBuf::from("x/file-b")),
                (true, PathBuf::from("y/file-a")),
                (true, PathBuf::from("y/file-b")),
                (true, PathBuf::from("z/file-a")),
                (false, PathBuf::from("z/folder-a/file-a")),
                (false, PathBuf::from("z/folder-b/file-a")),
                (true, PathBuf::from("z/folder-b/file-b")),
            ]
        );
    }
}
