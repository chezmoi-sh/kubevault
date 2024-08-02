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

use anyhow::{Context, Ok, Result};
use glob_match::glob_match;
use k8s_openapi::{
    api::{
        core::v1::{Secret, ServiceAccount},
        rbac::v1::{PolicyRule, Role, RoleBinding},
    },
    apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference},
};
use lazy_static::lazy_static;
use regex::Regex;
use serde_yaml;
use std::{collections::BTreeMap, fs, path, str::FromStr};

/// Generate the Secret manifests from the kvstore directory
pub fn generate_secret_manifests(
    vault_dir: VaultDir,
    namespace: &str,
    secrets: Vec<path::PathBuf>,
) -> Result<Vec<Secret>> {
    let mut manifests: Vec<Secret> = Vec::new();
    for path in secrets {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Unable to read secret {:?}", &path))?;
        let content: BTreeMap<String, String> = serde_yaml::from_str(&content)
            .with_context(|| format!("Unable to parse YAML content from secret {:?}", &path))?;

        let name = path
            .strip_prefix(vault_dir.kvstore_directory())
            .with_context(|| {
                format!(
                    "Unable to strip prefix {:?} from {:?}",
                    vault_dir.kvstore_directory(),
                    &path
                )
            })?
            .to_str()
            .with_context(|| format!("Unable to convert path {:?} to string", &path))?
            .to_string();

        manifests.push(Secret {
            metadata: ObjectMeta {
                annotations: Some(BTreeMap::from([(
                    "kubevault.chezmoi.sh/source".to_string(),
                    name.clone(),
                )])),
                name: Some(enforce_dns1035_format(name.as_str())?),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            type_: Some("Opaque".to_string()),
            string_data: Some(content),
            ..Default::default()
        });
    }

    Ok(manifests)
}

/// Generate the RBAC manifests for all the accounts in the access control directory
pub fn generate_rbac_manifests(
    vault_dir: VaultDir,
    namespace: &str,
    users: Vec<path::PathBuf>,
    secrets: Vec<path::PathBuf>,
) -> Result<Vec<(ServiceAccount, Secret, Role, RoleBinding)>> {
    let mut secrets = secrets
        .iter()
        .map(|path| {
            path.strip_prefix(vault_dir.kvstore_directory())
                .with_context(|| {
                    format!(
                        "Unable to strip prefix {:?} from {:?}",
                        vault_dir.kvstore_directory(),
                        &path
                    )
                })
                .map(|path| path.to_path_buf())
        })
        .collect::<Result<Vec<_>>>()?;
    secrets.sort();

    let mut manifests: Vec<(ServiceAccount, Secret, Role, RoleBinding)> = Vec::new();

    for user in users {
        let account_name = user.file_name().unwrap().to_str().unwrap().to_string();
        let content = fs::read_to_string(&user).with_context(|| {
            format!(
                "Unable to read access control rules for {:?} on {:?}",
                &account_name, &user
            )
        })?;
        let access_rules = content
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.trim().to_string())
            .collect::<Vec<_>>();

        let allowed_secrets = get_access_control_list(access_rules.clone(), secrets.clone())
            .into_iter()
            .filter_map(|(access, path)| {
                if access {
                    Some(enforce_dns1035_format(path.as_os_str().to_str().unwrap()).unwrap())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        manifests.push((
            ServiceAccount {
                metadata: ObjectMeta {
                    name: Some(account_name.to_string()),
                    namespace: Some(namespace.to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
            Secret {
                metadata: ObjectMeta {
                    annotations: Some(std::collections::BTreeMap::from([(
                        "kubernetes.io/service-account.name".to_string(),
                        account_name.to_string(),
                    )])),
                    name: Some(account_name.to_string()),
                    namespace: Some(namespace.to_string()),
                    owner_references: Some(vec![OwnerReference {
                        api_version: "v1".to_string(),
                        kind: "ServiceAccount".to_string(),
                        name: account_name.to_string(),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
                type_: Some("kubernetes.io/service-account-token".to_string()),
                ..Default::default()
            },
            Role {
                metadata: ObjectMeta {
                    annotations: Some(std::collections::BTreeMap::from([(
                        "kubevault.chezmoi.sh/rules".to_string(),
                        access_rules.join("\n").to_string(),
                    )])),
                    name: Some(format!("kubevault:{}:access", &account_name)),
                    namespace: Some(namespace.to_string()),
                    ..Default::default()
                },
                rules: Some(vec![
                    PolicyRule {
                        api_groups: Some(vec!["authorization.k8s.io".to_string()]),
                        resources: Some(vec!["selfsubjectaccessreviews".to_string()]),
                        verbs: vec!["create".to_string()],
                        ..Default::default()
                    },
                    PolicyRule {
                        api_groups: Some(vec!["".to_string()]),
                        resources: Some(vec!["secrets".to_string()]),
                        resource_names: Some(allowed_secrets),
                        verbs: vec!["get".to_string(), "list".to_string()],
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            },
            RoleBinding {
                metadata: ObjectMeta {
                    name: Some(format!("kubevault:{}:access", &account_name)),
                    namespace: Some(namespace.to_string()),
                    ..Default::default()
                },
                role_ref: k8s_openapi::api::rbac::v1::RoleRef {
                    api_group: "rbac.authorization.k8s.io".to_string(),
                    kind: "Role".to_string(),
                    name: format!("kubevault:{}:access", &account_name),
                },
                subjects: Some(vec![k8s_openapi::api::rbac::v1::Subject {
                    api_group: None,
                    kind: "ServiceAccount".to_string(),
                    name: account_name.to_string(),
                    namespace: Some(namespace.to_string()),
                }]),
            },
        ));
    }

    Ok(manifests)
}

/// Generate the list of secrets that are accessible by the given access rules
pub fn get_access_control_list(
    access_rules: Vec<String>,
    secrets: Vec<path::PathBuf>,
) -> Vec<(bool, path::PathBuf)> {
    let mut allowed_secrets = secrets
        .into_iter()
        .map(|path| (false, path))
        .collect::<Vec<_>>();

    for rule in &access_rules {
        allowed_secrets.iter_mut().for_each(|(access, path)| {
            if !rule.starts_with("!") {
                *access = glob_match(&rule, path.to_str().unwrap()) || *access;
            } else {
                *access = !glob_match(&rule[1..], path.to_str().unwrap()) && *access;
            }
        });
    }

    allowed_secrets
}

// Vault represents the path to the directory where the kubevault configuration
// and secret are stored
#[derive(Clone, Debug)]
pub struct VaultDir(path::PathBuf);

const ACCESS_CONTROL_DIRECTORY: &str = "access_control";
const KVSTORE_DIRECTORY: &str = "kvstore";

impl FromStr for VaultDir {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let path = path::PathBuf::from(s);
        if !path.exists() {
            anyhow::bail!("The Vault directory '{}' does not exist", s);
        } else if !path.is_dir() {
            anyhow::bail!("The Vault directory '{}' is not a directory", s);
        }

        if !path.join(ACCESS_CONTROL_DIRECTORY).exists()
            || !path.join(ACCESS_CONTROL_DIRECTORY).is_dir()
        {
            anyhow::bail!(
                "The Vault directory '{}' must contains an access control directory ({})",
                s,
                ACCESS_CONTROL_DIRECTORY
            );
        } else if !path.join(KVSTORE_DIRECTORY).exists() || !path.join(KVSTORE_DIRECTORY).is_dir() {
            anyhow::bail!(
                "The Vault directory '{}' must contains a key-value store directory ({})",
                s,
                KVSTORE_DIRECTORY
            );
        }

        Ok(VaultDir(path))
    }
}

impl VaultDir {
    // access_control_directory returns the path to the access control directory
    pub fn access_control_directory(&self) -> path::PathBuf {
        self.0.join(ACCESS_CONTROL_DIRECTORY)
    }

    // kvstore_directory returns the path to the key-value store directory
    pub fn kvstore_directory(&self) -> path::PathBuf {
        self.0.join(KVSTORE_DIRECTORY)
    }
}

lazy_static! {
    static ref RX_INVALID_DNS1035_HEAD: Regex = Regex::new(r"^[a-z]").unwrap();
    static ref RX_INVALID_DNS1035_CHAR: Regex = Regex::new(r"[^-a-z0-9]").unwrap();
    static ref RX_INVALID_DNS1035_TAIL: Regex = Regex::new(r"[a-z0-9]$").unwrap();
}

/// Enforce DNS1035 format for a string
pub fn enforce_dns1035_format(name: &str) -> anyhow::Result<String> {
    let mut name = name.to_lowercase();

    if !RX_INVALID_DNS1035_HEAD.is_match(&name) || !RX_INVALID_DNS1035_TAIL.is_match(&name) {
        anyhow::bail!(
            "Invalid DNS1035 name {:?}: must validate '^[a-z][a-z0-9-]*[a-z0-9]$",
            name
        );
    } else if RX_INVALID_DNS1035_CHAR.is_match(&name) {
        name = RX_INVALID_DNS1035_CHAR.replace_all(&name, "-").to_string();
    }
    return Ok(name);
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
            path::PathBuf::from("x/file-a"),
            path::PathBuf::from("x/file-b"),
            path::PathBuf::from("y/file-a"),
            path::PathBuf::from("y/file-b"),
            path::PathBuf::from("z/file-a"),
            path::PathBuf::from("z/folder-a/file-a"),
            path::PathBuf::from("z/folder-b/file-a"),
            path::PathBuf::from("z/folder-b/file-b"),
            path::PathBuf::from("a/b/c/file-a"),
            path::PathBuf::from("a/b/c/file-b"),
            path::PathBuf::from("a/b/d/file-a"),
            path::PathBuf::from("a/b/d/file-b"),
        ];

        assert_eq!(
            get_access_control_list(access_rules, secrets),
            vec![
                (false, path::PathBuf::from("x/file-a")),
                (false, path::PathBuf::from("x/file-b")),
                (true, path::PathBuf::from("y/file-a")),
                (true, path::PathBuf::from("y/file-b")),
                (true, path::PathBuf::from("z/file-a")),
                (false, path::PathBuf::from("z/folder-a/file-a")),
                (false, path::PathBuf::from("z/folder-b/file-a")),
                (false, path::PathBuf::from("z/folder-b/file-b")),
                (false, path::PathBuf::from("a/b/c/file-a")),
                (true, path::PathBuf::from("a/b/c/file-b")),
                (true, path::PathBuf::from("a/b/d/file-a")),
                (true, path::PathBuf::from("a/b/d/file-b")),
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
            path::PathBuf::from("x/file-a"),
            path::PathBuf::from("x/file-b"),
            path::PathBuf::from("y/file-a"),
            path::PathBuf::from("y/file-b"),
            path::PathBuf::from("z/file-a"),
            path::PathBuf::from("z/folder-a/file-a"),
            path::PathBuf::from("z/folder-b/file-a"),
            path::PathBuf::from("z/folder-b/file-b"),
            path::PathBuf::from("a/b/c/file-a"),
            path::PathBuf::from("a/b/c/file-b"),
            path::PathBuf::from("a/b/d/file-a"),
            path::PathBuf::from("a/b/d/file-b"),
        ];

        assert_eq!(
            get_access_control_list(access_rules, secrets),
            vec![
                (false, path::PathBuf::from("x/file-a")),
                (false, path::PathBuf::from("x/file-b")),
                (true, path::PathBuf::from("y/file-a")),
                (true, path::PathBuf::from("y/file-b")),
                (true, path::PathBuf::from("z/file-a")),
                (false, path::PathBuf::from("z/folder-a/file-a")),
                (false, path::PathBuf::from("z/folder-b/file-a")),
                (true, path::PathBuf::from("z/folder-b/file-b")),
                (false, path::PathBuf::from("a/b/c/file-a")),
                (false, path::PathBuf::from("a/b/c/file-b")),
                (true, path::PathBuf::from("a/b/d/file-a")),
                (true, path::PathBuf::from("a/b/d/file-b")),
            ]
        );
    }
}
