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
use k8s_openapi::api::core::v1::{Secret, ServiceAccount};
use k8s_openapi::api::rbac;
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, RoleBinding};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use std::collections::BTreeMap;
use std::io::Write;
use std::{fs, path::PathBuf};
use walkdir::WalkDir;

use super::{ACCESS_CONTROL_DIRECTORY, KVSTORE_DIRECTORY};
use kubevault::{enforce_dns1035_format, get_access_control_list};

#[derive(Debug, Parser)]
#[command(about = "Generate all Kubernetes manifests")]
pub struct Command {
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
    output_dir: Option<PathBuf>,

    #[arg(
        help = "Path to the directory where the kubevault configuration is stored",
        long,
        env = "KUBEVAULT_DIR",
        default_value = "vault",
        value_name = "PATH",
        value_hint = clap::ValueHint::DirPath
    )]
    vault_dir: PathBuf,
}

impl Command {
    pub fn run(&self) -> Result<()> {
        let mut secrets: Vec<PathBuf> = Vec::new();
        for entry in WalkDir::new(self.vault_dir.join(KVSTORE_DIRECTORY)) {
            let entry = entry.with_context(|| {
                format!(
                    "Failed to read directory {:?}",
                    self.vault_dir.join(KVSTORE_DIRECTORY)
                )
            })?;

            if entry.file_type().is_file() {
                secrets.push(entry.path().to_owned());
            }
        }

        let mut users: Vec<PathBuf> = Vec::new();
        for entry in WalkDir::new(self.vault_dir.join(ACCESS_CONTROL_DIRECTORY)) {
            let entry = entry.with_context(|| {
                format!(
                    "Failed to read directory {:?}",
                    self.vault_dir.join(ACCESS_CONTROL_DIRECTORY)
                )
            })?;

            if entry.file_type().is_file() {
                users.push(entry.path().to_owned());
            }
        }

        let secret_manifests =
            generate_secret_manifests(self.vault_dir.clone(), &self.namespace, &secrets)?;
        let rbac_manifests =
            generate_rbac_manifests(self.vault_dir.clone(), &self.namespace, &users, &secrets)?;

        match self.output_dir.clone() {
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
                    file.write_all("---\n".as_bytes())?;
                    serde_yaml::to_writer(&file, &secret).with_context(|| {
                        format!("Failed to write access control manifests {:?}", &path)
                    })?;
                    file.write_all("---\n".as_bytes())?;
                    serde_yaml::to_writer(&file, &role).with_context(|| {
                        format!("Failed to write access control manifests {:?}", &path)
                    })?;
                    file.write_all("---\n".as_bytes())?;
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
}

/// Generate the Secret manifests from the kvstore directory
pub fn generate_secret_manifests(
    vault_dir: PathBuf,
    namespace: &str,
    secrets: &[PathBuf],
) -> Result<Vec<Secret>> {
    let mut manifests: Vec<Secret> = Vec::new();
    for path in secrets {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Unable to read secret {:?}", &path))?;
        let content: BTreeMap<String, String> = serde_yaml::from_str(&content)
            .with_context(|| format!("Unable to parse YAML content from secret {:?}", &path))?;

        let name = path
            .strip_prefix(vault_dir.join(KVSTORE_DIRECTORY))
            .with_context(|| {
                format!(
                    "Unable to strip prefix {:?} from {:?}",
                    vault_dir.join(KVSTORE_DIRECTORY),
                    path
                )
            })?;

        manifests.push(Secret {
            metadata: ObjectMeta {
                annotations: Some(BTreeMap::from([(
                    "kubevault.chezmoi.sh/source".to_string(),
                    name.to_str().unwrap().replace('\\', "/"),
                )])),
                name: Some(enforce_dns1035_format(name.to_str().unwrap())?),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            type_: Some("Opaque".to_string()),
            string_data: Some(content),
            ..Default::default()
        });
    }

    manifests.sort_by(|a, b| a.metadata.name.cmp(&b.metadata.name));
    Ok(manifests)
}

/// Generate the RBAC manifests for all the accounts in the access control directory
pub fn generate_rbac_manifests(
    vault_dir: PathBuf,
    namespace: &str,
    users: &[PathBuf],
    secrets: &[PathBuf],
) -> Result<Vec<(ServiceAccount, Secret, Role, RoleBinding)>> {
    let secrets = secrets
        .iter()
        .map(|path| {
            path.strip_prefix(vault_dir.join(KVSTORE_DIRECTORY))
                .with_context(|| {
                    format!(
                        "Unable to strip prefix {:?} from {:?}",
                        vault_dir.join(KVSTORE_DIRECTORY),
                        path
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut secrets = secrets
        .into_iter()
        .map(|path| path.to_path_buf())
        .collect::<Vec<_>>();
    secrets.sort();

    let mut manifests: Vec<(ServiceAccount, Secret, Role, RoleBinding)> = Vec::new();

    for user in users {
        let account_name = user.file_name().unwrap().to_str().unwrap().to_string();
        let content = fs::read_to_string(user).with_context(|| {
            format!(
                "Unable to read access control rules for {:?} on {:?}",
                account_name, user
            )
        })?;
        let access_rules = content
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.trim().to_string())
            .collect::<Vec<_>>();

        let allowed_secrets = get_access_control_list(&access_rules, &secrets)
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
                    annotations: Some(BTreeMap::from([(
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
                    annotations: Some(BTreeMap::from([(
                        "kubevault.chezmoi.sh/rules".to_string(),
                        access_rules.join("\n").to_string(),
                    )])),
                    name: Some(format!("kubevault:{}:read", &account_name)),
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
            },
            RoleBinding {
                metadata: ObjectMeta {
                    name: Some(format!("kubevault:{}:read", &account_name)),
                    namespace: Some(namespace.to_string()),
                    ..Default::default()
                },
                role_ref: rbac::v1::RoleRef {
                    api_group: "rbac.authorization.k8s.io".to_string(),
                    kind: "Role".to_string(),
                    name: format!("kubevault:{}:read", &account_name),
                },
                subjects: Some(vec![rbac::v1::Subject {
                    api_group: None,
                    kind: "ServiceAccount".to_string(),
                    name: account_name.to_string(),
                    namespace: Some(namespace.to_string()),
                }]),
            },
        ));
    }

    manifests.sort_by(|a, b| a.0.metadata.name.cmp(&b.0.metadata.name));
    Ok(manifests)
}
