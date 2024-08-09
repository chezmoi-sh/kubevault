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
use futures::executor::block_on;
use http::Uri;
use k8s_openapi::api::core::v1::Secret;
use kube::{api::ObjectMeta, config::KubeConfigOptions, Api, Client};
use kube_custom_resources_rs::external_secrets_io::v1beta1::clustersecretstores::{
    ClusterSecretStore, ClusterSecretStoreProvider, ClusterSecretStoreProviderKubernetes,
    ClusterSecretStoreProviderKubernetesAuth, ClusterSecretStoreProviderKubernetesAuthToken,
    ClusterSecretStoreProviderKubernetesAuthTokenBearerToken,
    ClusterSecretStoreProviderKubernetesServer,
    ClusterSecretStoreProviderKubernetesServerCaProvider,
    ClusterSecretStoreProviderKubernetesServerCaProviderType, ClusterSecretStoreSpec,
};
use kube_custom_resources_rs::external_secrets_io::v1beta1::secretstores::{
    SecretStore, SecretStoreProvider, SecretStoreProviderKubernetes,
    SecretStoreProviderKubernetesAuth, SecretStoreProviderKubernetesAuthToken,
    SecretStoreProviderKubernetesAuthTokenBearerToken, SecretStoreProviderKubernetesServer,
    SecretStoreProviderKubernetesServerCaProvider,
    SecretStoreProviderKubernetesServerCaProviderType, SecretStoreSpec,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(about = "Generate Kubernetes manifests required to use an external-secret")]
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

    #[arg(
        help = "URL of the kubevault's Kubernetes API",
        long,
        value_name = "URL",
        value_hint = clap::ValueHint::Url,
        value_parser = clap::value_parser!(Uri)
    )]
    vault_url: Option<Uri>,

    #[arg(
        help = "The name of Kubernetes context to use",
        long,
        value_name = "CONTEXT",
        value_parser = clap::builder::NonEmptyStringValueParser::new()
    )]
    context: Option<String>,

    #[arg(
        help = "Namespace where the kvstore is installed",
        long,
        short = 'n',
        env = "KUBEVAULT_NAMESPACE",
        default_value = "kubevault-kvstore",
        value_name = "NAMESPACE",
        value_parser = clap::builder::NonEmptyStringValueParser::new()
    )]
    namespace: String,

    #[arg(help = "Create a ClusterSecretStore instead of a SecretStore", long)]
    clustered: bool,

    #[arg(
        help = "The name of the user to generate the manifests for",
        value_name = "NAME",
        value_parser = clap::builder::NonEmptyStringValueParser::new()
    )]
    user: String,
}

impl Command {
    pub fn run(&self, io_out: impl std::io::Write) -> Result<()> {
        block_on(async {
            let config: kube::Config = match self.context.clone() {
                Some(context) => kube::Config::from_kubeconfig(&KubeConfigOptions {
                    context: Some(context.clone()),
                    ..Default::default()
                })
                .await
                .with_context(|| {
                    format!(
                        "Failed to create a Kubernetes client using the Kubernetes context '{}'",
                        context
                    )
                })?,

                None => kube::Config::infer()
                    .await
                    .with_context(|| "Failed to infer configuration from the environment")?,
            };

            let client = Client::try_from(config.clone()).with_context(|| {
                format!(
                    "Failed to create a Kubernetes client using the Kubernetes context '{}'",
                    self.context.as_deref().unwrap()
                )
            })?;

            let vault_url = self.vault_url.clone().unwrap_or(config.cluster_url);
            self.async_run(io_out, client, vault_url).await
        })
    }

    async fn async_run(
        &self,
        mut io_out: impl std::io::Write,
        client: Client,
        vault_url: Uri,
    ) -> Result<()> {
        let secrets: Api<Secret> = Api::namespaced(client, self.namespace.as_str());
        let user_secret = secrets.get(&self.user).await.with_context(|| {
            format!(
                "User '{:?}' does not exist or not deployed in namespace {:?}",
                self.user, self.namespace
            )
        })?;

        if user_secret.type_.as_deref().unwrap_or_default() != "kubernetes.io/service-account-token"
        {
            anyhow::bail!(
                "Secret {:?} is not a service account token secret",
                self.user
            );
        }

        let mut secret = user_secret.clone();
        let secret_name = format!("kubevault-{}", self.user);
        let mut secret_data = secret.data.unwrap_or_default();
        secret_data.remove_entry("namespace");

        secret.type_ = Some("Opaque".to_string());
        secret.metadata = ObjectMeta {
            name: Some(secret_name.clone()),
            ..Default::default()
        };
        secret.data = Some(secret_data);

        let secret_yaml = serde_yaml::to_string(&secret)?;
        writeln!(io_out, "---\n{}", secret_yaml)?;

        let namespace = self.namespace.clone();
        if self.clustered {
            let store = ClusterSecretStore::new(
                vault_url.host().unwrap(),
                ClusterSecretStoreSpec {
                    provider: ClusterSecretStoreProvider {
                        kubernetes: Some(ClusterSecretStoreProviderKubernetes {
                            remote_namespace: Some(namespace),
                            server: Some(ClusterSecretStoreProviderKubernetesServer {
                                url: Some(vault_url.to_string()),
                                ca_provider: Some(ClusterSecretStoreProviderKubernetesServerCaProvider {
                                    r#type: ClusterSecretStoreProviderKubernetesServerCaProviderType::Secret,
                                    name: secret_name.clone(),
                                    namespace: None,
                                    key: Some("ca.crt".to_string()),
                                }),
                                ca_bundle: None,
                            }),
                            auth: ClusterSecretStoreProviderKubernetesAuth {
                                token: Some(ClusterSecretStoreProviderKubernetesAuthToken {
                                    bearer_token: Some(ClusterSecretStoreProviderKubernetesAuthTokenBearerToken {
                                        name: Some(secret_name),
                                        namespace: None,
                                        key: Some("token".to_string()),
                                    }),
                                }),
                                cert: None,
                                service_account: None
                            },
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                });

            let store_yaml = serde_yaml::to_string(&store)?;
            writeln!(io_out, "---\n{}", store_yaml)?;
        } else {
            let store = SecretStore::new(
                vault_url.host().unwrap(),
                SecretStoreSpec {
                    provider: SecretStoreProvider {
                        kubernetes: Some(SecretStoreProviderKubernetes {
                            remote_namespace: Some(namespace),
                            server: Some(SecretStoreProviderKubernetesServer {
                                url: Some(vault_url.to_string()),
                                ca_provider: Some(SecretStoreProviderKubernetesServerCaProvider {
                                    r#type:
                                        SecretStoreProviderKubernetesServerCaProviderType::Secret,
                                    name: secret_name.clone(),
                                    namespace: None,
                                    key: Some("ca.crt".to_string()),
                                }),
                                ca_bundle: None,
                            }),
                            auth: SecretStoreProviderKubernetesAuth {
                                token: Some(SecretStoreProviderKubernetesAuthToken {
                                    bearer_token: Some(
                                        SecretStoreProviderKubernetesAuthTokenBearerToken {
                                            name: Some(secret_name),
                                            namespace: None,
                                            key: Some("token".to_string()),
                                        },
                                    ),
                                }),
                                cert: None,
                                service_account: None,
                            },
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );

            let store_yaml = serde_yaml::to_string(&store)?;
            writeln!(io_out, "---\n{}", store_yaml)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use assert_fs::TempDir;
    use similar_asserts::assert_eq;
    use std::fs;

    #[tokio::test]
    async fn test_external_secret_store_no_kubeconfig() {
        let command = super::Command {
            vault_dir: std::path::PathBuf::from("vault"),
            vault_url: None,
            context: None,
            namespace: "kubevault-kvstore".to_string(),
            clustered: false,
            user: "default".to_string(),
        };

        std::env::remove_var("KUBECONFIG");
        let result = command.run(std::io::sink());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to infer configuration from the environment"
        );
    }

    #[tokio::test]
    async fn test_external_secret_store_with_invalid_context() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let kubeconfig_path = temp_dir.path().join("kubeconfig");
        fs::write(
            &kubeconfig_path,
            "---
---
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ''
    server: https://localhost:6443
  name: default
contexts:
- context:
    cluster: default
    user: admin@default
  name: default
users:
- name: admin@default
  user:
    client-certificate-data: ''
    client-key-data: ''
",
        )
        .expect("Failed to write kubeconfig");
        std::env::set_var("KUBECONFIG", kubeconfig_path.as_os_str());

        let command = super::Command {
            vault_dir: std::path::PathBuf::from("vault"),
            vault_url: None,
            context: Some("invalid".to_string()),
            namespace: "kubevault-kvstore".to_string(),
            clustered: false,
            user: "default".to_string(),
        };

        let result = command.run(std::io::sink());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to create a Kubernetes client using the Kubernetes context 'invalid'"
        );
    }
}
