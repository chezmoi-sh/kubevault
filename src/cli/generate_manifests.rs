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
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
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
    pub fn run(&self, mut io_out: impl Write) -> Result<()> {
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
                    writeln!(io_out, "---")?;
                    write!(io_out, "{}", serde_yaml::to_string(&secret)?)?;
                }

                for (sa, secret, role, binding) in rbac_manifests.iter() {
                    writeln!(io_out, "---")?;
                    write!(io_out, "{}", serde_yaml::to_string(sa)?)?;
                    writeln!(io_out, "---")?;
                    write!(io_out, "{}", serde_yaml::to_string(secret)?)?;
                    writeln!(io_out, "---")?;
                    write!(io_out, "{}", serde_yaml::to_string(role)?)?;
                    writeln!(io_out, "---")?;
                    write!(io_out, "{}", serde_yaml::to_string(binding)?)?;
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

#[cfg(test)]
mod test {
    use super::*;
    use assert_fs::TempDir;
    use similar_asserts::assert_eq;

    #[test]
    fn test_generate_secret_manifests_no_secrets() {
        let vault_dir = PathBuf::from("/path/to/nonexistent/vault");
        let secrets = vec![];

        let manifests = generate_secret_manifests(vault_dir.clone(), "default", &secrets);
        assert!(manifests.is_ok());
        assert_eq!(manifests.unwrap(), vec![]);
    }

    #[test]
    fn test_generate_secret_manifests_single_no_vault_directory() {
        let vault_dir = PathBuf::from("/path/to/nonexistent/vault");
        let secrets = vec![vault_dir.join(KVSTORE_DIRECTORY).join("secret.yaml")];

        let manifests = generate_secret_manifests(vault_dir.clone(), "default", &secrets);
        assert!(manifests.is_err());
        assert_eq!(
            manifests.unwrap_err().to_string(),
            format!(
                "Unable to read secret {:?}",
                vault_dir.join(KVSTORE_DIRECTORY).join("secret.yaml")
            )
        );
    }

    #[test]
    fn test_generate_secret_manifests_invalid_secret() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let kvstore_dir = vault_dir.join(KVSTORE_DIRECTORY);
        fs::create_dir_all(&kvstore_dir).expect("Failed to create kvstore directory");

        let secret_path = kvstore_dir.join("secret.yaml");
        fs::write(&secret_path, "// invalid yaml").expect("Failed to write secret.yaml");

        let manifests =
            generate_secret_manifests(vault_dir.clone(), "default", &[secret_path.clone()]);
        assert!(manifests.is_err());
        assert_eq!(
            manifests.unwrap_err().to_string(),
            format!("Unable to parse YAML content from secret {:?}", secret_path)
        );
    }

    #[test]
    fn test_generate_secret_manifests_invalid_secret_name() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let kvstore_dir = vault_dir.join(KVSTORE_DIRECTORY);
        fs::create_dir_all(&kvstore_dir).expect("Failed to create kvstore directory");

        let secret_path = kvstore_dir.join("ō invalid name.yaml");
        fs::write(&secret_path, "key: value").expect("Failed to write invalid-name.yaml");

        let manifests =
            generate_secret_manifests(vault_dir.clone(), "default", &[secret_path.clone()]);
        assert!(manifests.is_err());
        assert_eq!(manifests.unwrap_err().to_string(), "Invalid DNS1035 name \"ō invalid name.yaml\": must validate '^[a-z][a-z0-9-]*[a-z0-9]$");
    }

    #[test]
    fn test_generate_secret_manifests_with_secrets() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let kvstore_dir = vault_dir.join(KVSTORE_DIRECTORY);
        fs::create_dir_all(&kvstore_dir).expect("Failed to create kvstore directory");

        let secrets = vec![
            kvstore_dir.join("secret1.yaml"),
            kvstore_dir.join("secret2.yaml"),
            kvstore_dir.join("dir1").join("secret3.yaml"),
            kvstore_dir
                .join("dir1")
                .join("subdir1")
                .join("secret4.yaml"),
        ];
        for secret in &secrets {
            fs::create_dir_all(secret.parent().unwrap())
                .expect("Failed to create secret directory");
            fs::write(secret, "key: value").expect("Failed to write secret.yaml");
        }

        let manifests = generate_secret_manifests(vault_dir.clone(), "default", &secrets);
        assert!(manifests.is_ok());

        let manifests = manifests.unwrap();
        assert_eq!(manifests.len(), 4);
        assert_eq!(
            manifests
                .iter()
                .map(|m| m.metadata.name.as_ref().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "dir1-secret3-yaml",
                "dir1-subdir1-secret4-yaml",
                "secret1-yaml",
                "secret2-yaml",
            ]
        );
    }

    // generate_rbac_manifests
    #[test]
    fn test_generate_rbac_manifests_no_users() {
        let vault_dir = PathBuf::from("/path/to/nonexistent/vault");
        let users = vec![];
        let secrets = vec![];

        let manifests = generate_rbac_manifests(vault_dir.clone(), "default", &users, &secrets);
        assert!(manifests.is_ok());
        assert_eq!(manifests.unwrap(), vec![]);
    }

    #[test]
    fn test_generate_rbac_manifests_no_secret() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let access_control_dir = vault_dir.join(ACCESS_CONTROL_DIRECTORY);
        fs::create_dir_all(&access_control_dir).expect("Failed to create access control directory");

        let user = access_control_dir.join("user");
        fs::write(&user, "").expect("Failed to write user");

        let manifests = generate_rbac_manifests(vault_dir.clone(), "default", &[user], &[]);
        assert!(manifests.is_ok());

        let (sa, secret, role, binding) = &manifests.unwrap()[0];
        assert_eq!(sa.metadata.name.as_ref().unwrap(), "user");
        assert_eq!(secret.metadata.name.as_ref().unwrap(), "user");
        assert_eq!(role.metadata.name.as_ref().unwrap(), "kubevault:user:read");
        assert_eq!(
            role.metadata
                .annotations
                .as_ref()
                .unwrap()
                .get("kubevault.chezmoi.sh/rules")
                .unwrap(),
            ""
        );
        assert_eq!(
            role.rules.clone().unwrap(),
            vec![
                PolicyRule {
                    api_groups: Some(vec!["authorization.k8s.io".to_string()]),
                    resources: Some(vec!["selfsubjectaccessreviews".to_string()]),
                    verbs: vec!["create".to_string()],
                    ..Default::default()
                },
                PolicyRule {
                    api_groups: Some(vec!["".to_string()]),
                    resources: Some(vec!["secrets".to_string()]),
                    resource_names: Some(vec![]),
                    verbs: vec!["get".to_string(), "list".to_string()],
                    ..Default::default()
                },
            ]
        );
        assert_eq!(
            binding.metadata.name.as_ref().unwrap(),
            "kubevault:user:read"
        );
        assert_eq!(binding.role_ref.name, "kubevault:user:read");
        assert_eq!(binding.subjects.clone().unwrap()[0].name, "user");
    }

    #[test]
    fn test_generate_rbac_manifests_single_no_vault_directory() {
        let vault_dir = PathBuf::from("/path/to/nonexistent/vault");

        let manifests = generate_rbac_manifests(
            vault_dir.clone(),
            "default",
            &[vault_dir.join(ACCESS_CONTROL_DIRECTORY).join("user")],
            &[],
        );
        assert!(manifests.is_err());
        assert_eq!(
            manifests.unwrap_err().to_string(),
            format!(
                "Unable to read access control rules for \"user\" on {:?}",
                vault_dir.join(ACCESS_CONTROL_DIRECTORY).join("user")
            )
        );
    }

    #[test]
    fn test_generate_rbac_manifests_mixed_access_rules() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let kvstore_dir = vault_dir.join(KVSTORE_DIRECTORY);
        let access_control_dir = vault_dir.join(ACCESS_CONTROL_DIRECTORY);
        fs::create_dir_all(&access_control_dir).expect("Failed to create access control directory");

        let secrets = vec![
            kvstore_dir.join("secret1.yaml"),
            kvstore_dir.join("secret2.yaml"),
            kvstore_dir.join("dir1").join("secret3.yaml"),
            kvstore_dir
                .join("dir1")
                .join("subdir1")
                .join("secret4.yaml"),
        ];
        for secret in &secrets {
            fs::create_dir_all(secret.parent().unwrap())
                .expect("Failed to create secret directory");
            fs::write(secret, "key: value").expect("Failed to write secret.yaml");
        }

        let user = access_control_dir.join("user1");
        fs::write(
            user.clone(),
            "secret1.yaml\n!secret2.yaml\n**/secret3.yaml\n!**/secret4.yaml",
        )
        .expect("Failed to write access control rules");

        let manifests = generate_rbac_manifests(vault_dir.clone(), "default", &[user], &secrets);
        assert!(manifests.is_ok());

        let manifests = manifests.unwrap();
        assert_eq!(manifests.len(), 1);

        let (sa, secret, role, binding) = &manifests[0];
        let expected_name = "user1";

        assert_eq!(sa.metadata.name.as_ref().unwrap(), expected_name);
        assert_eq!(secret.metadata.name.as_ref().unwrap(), expected_name);
        assert_eq!(
            role.metadata.name.as_ref().unwrap(),
            &format!("kubevault:{}:read", expected_name)
        );
        assert_eq!(
            role.metadata
                .annotations
                .as_ref()
                .unwrap()
                .get("kubevault.chezmoi.sh/rules")
                .unwrap(),
            "secret1.yaml\n!secret2.yaml\n**/secret3.yaml\n!**/secret4.yaml"
        );
        assert_eq!(
            role.rules.clone().unwrap(),
            vec![
                PolicyRule {
                    api_groups: Some(vec!["authorization.k8s.io".to_string()]),
                    resources: Some(vec!["selfsubjectaccessreviews".to_string()]),
                    verbs: vec!["create".to_string()],
                    ..Default::default()
                },
                PolicyRule {
                    api_groups: Some(vec!["".to_string()]),
                    resources: Some(vec!["secrets".to_string()]),
                    resource_names: Some(vec![
                        "dir1-secret3-yaml".to_string(),
                        "secret1-yaml".to_string()
                    ]),
                    verbs: vec!["get".to_string(), "list".to_string()],
                    ..Default::default()
                },
            ]
        );
        assert_eq!(
            binding.metadata.name.as_ref().unwrap(),
            &format!("kubevault:{}:read", expected_name)
        );
        assert_eq!(
            binding.role_ref.name,
            format!("kubevault:{}:read", expected_name)
        );
    }

    #[test]
    fn test_command_run_no_kvstore_directory() {
        let vault_dir = PathBuf::from("/path/to/nonexistent/vault");

        let command = Command {
            namespace: "default".to_string(),
            output_dir: None,
            vault_dir: vault_dir.clone(),
        };

        let result = command.run(Vec::new());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            format!(
                "Failed to read directory {:?}",
                vault_dir.join(KVSTORE_DIRECTORY)
            )
        );
    }

    #[test]
    fn test_command_run_no_access_control_directory() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let kvstore_dir = vault_dir.join(KVSTORE_DIRECTORY);
        fs::create_dir_all(&kvstore_dir).expect("Failed to create kvstore directory");

        let command = Command {
            namespace: "default".to_string(),
            output_dir: None,
            vault_dir: vault_dir.clone(),
        };

        let result = command.run(Vec::new());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            format!(
                "Failed to read directory {:?}",
                vault_dir.join(ACCESS_CONTROL_DIRECTORY)
            )
        );
    }

    #[test]
    fn test_command_run_stdout() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let kvstore_dir = vault_dir.join(KVSTORE_DIRECTORY);
        let access_control_dir = vault_dir.join(ACCESS_CONTROL_DIRECTORY);
        fs::create_dir_all(&kvstore_dir).expect("Failed to create kvstore directory");
        fs::create_dir_all(&access_control_dir).expect("Failed to create access control directory");

        let secrets = vec![
            kvstore_dir.join("secret1.yaml"),
            kvstore_dir.join("secret2.yaml"),
            kvstore_dir.join("dir1/secret3.yaml"),
            kvstore_dir.join("dir1/subdir1/secret4.yaml"),
        ];
        for secret in &secrets {
            fs::create_dir_all(secret.parent().unwrap())
                .expect("Failed to create secret directory");
            fs::write(secret, "key: value").expect("Failed to write secret.yaml");
        }

        let user = access_control_dir.join("user1");
        fs::write(
            user.clone(),
            "secret1.yaml\n!secret2.yaml\n**/secret3.yaml\n!**/secret4.yaml",
        )
        .expect("Failed to write access control rules");

        let command = Command {
            namespace: "default".to_string(),
            output_dir: None,
            vault_dir: vault_dir.clone(),
        };

        let mut output = Vec::new();
        let result = command.run(&mut output);
        assert!(result.is_ok());

        assert_eq!(
            String::from_utf8(output).expect("Failed to convert output to string"),
            "---
apiVersion: v1
kind: Secret
metadata:
  annotations:
    kubevault.chezmoi.sh/source: dir1/secret3.yaml
  name: dir1-secret3-yaml
  namespace: default
stringData:
  key: value
type: Opaque
---
apiVersion: v1
kind: Secret
metadata:
  annotations:
    kubevault.chezmoi.sh/source: dir1/subdir1/secret4.yaml
  name: dir1-subdir1-secret4-yaml
  namespace: default
stringData:
  key: value
type: Opaque
---
apiVersion: v1
kind: Secret
metadata:
  annotations:
    kubevault.chezmoi.sh/source: secret1.yaml
  name: secret1-yaml
  namespace: default
stringData:
  key: value
type: Opaque
---
apiVersion: v1
kind: Secret
metadata:
  annotations:
    kubevault.chezmoi.sh/source: secret2.yaml
  name: secret2-yaml
  namespace: default
stringData:
  key: value
type: Opaque
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: user1
  namespace: default
---
apiVersion: v1
kind: Secret
metadata:
  annotations:
    kubernetes.io/service-account.name: user1
  name: user1
  namespace: default
type: kubernetes.io/service-account-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  annotations:
    kubevault.chezmoi.sh/rules: |-
      secret1.yaml
      !secret2.yaml
      **/secret3.yaml
      !**/secret4.yaml
  name: kubevault:user1:read
  namespace: default
rules:
- apiGroups:
  - authorization.k8s.io
  resources:
  - selfsubjectaccessreviews
  verbs:
  - create
- apiGroups:
  - ''
  resourceNames:
  - dir1-secret3-yaml
  - secret1-yaml
  resources:
  - secrets
  verbs:
  - get
  - list
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kubevault:user1:read
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: kubevault:user1:read
subjects:
- kind: ServiceAccount
  name: user1
  namespace: default
"
        )
    }

    #[test]
    fn test_command_run_output_dir() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let vault_dir = temp_dir.path().join("vault");
        let kvstore_dir = vault_dir.join(KVSTORE_DIRECTORY);
        let access_control_dir = vault_dir.join(ACCESS_CONTROL_DIRECTORY);
        fs::create_dir_all(&kvstore_dir).expect("Failed to create kvstore directory");
        fs::create_dir_all(&access_control_dir).expect("Failed to create access control directory");

        let secrets = vec![
            kvstore_dir.join("secret1.yaml"),
            kvstore_dir.join("secret2.yaml"),
            kvstore_dir.join("dir1").join("secret3.yaml"),
            kvstore_dir
                .join("dir1")
                .join("subdir1")
                .join("secret4.yaml"),
        ];
        for secret in &secrets {
            fs::create_dir_all(secret.parent().unwrap())
                .expect("Failed to create secret directory");
            fs::write(secret, "key: value").expect("Failed to write secret.yaml");
        }

        let user = access_control_dir.join("user1");
        fs::write(
            user.clone(),
            "secret1.yaml\n!secret2.yaml\n**/secret3.yaml\n!**/secret4.yaml",
        )
        .expect("Failed to write access control rules");

        let output_dir = temp_dir.path().join("output");
        fs::create_dir_all(&output_dir).expect("Failed to create output directory");

        let command = Command {
            namespace: "default".to_string(),
            output_dir: Some(output_dir.clone()),
            vault_dir: vault_dir.clone(),
        };

        let result = command.run(Vec::new());
        assert!(result.is_ok());

        let mut result = WalkDir::new(&output_dir)
            .into_iter()
            .filter_map(|entry| match entry {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        Some(entry.path().to_str().unwrap().to_string())
                    } else {
                        None
                    }
                }
                Err(_) => None,
            })
            .collect::<Vec<_>>();
        result.sort();
        assert_eq!(
            result,
            &[
                output_dir
                    .join("access-control-user1.yaml")
                    .to_str()
                    .unwrap()
                    .to_string(),
                output_dir
                    .join("secret-dir1-secret3-yaml.yaml")
                    .to_str()
                    .unwrap()
                    .to_string(),
                output_dir
                    .join("secret-dir1-subdir1-secret4-yaml.yaml")
                    .to_str()
                    .unwrap()
                    .to_string(),
                output_dir
                    .join("secret-secret1-yaml.yaml")
                    .to_str()
                    .unwrap()
                    .to_string(),
                output_dir
                    .join("secret-secret2-yaml.yaml")
                    .to_str()
                    .unwrap()
                    .to_string(),
            ]
        )
    }
}
