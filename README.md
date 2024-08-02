<!-- markdownlint-disable MD033 -->
<h1 align="center">
  chezmoi.sh · kubevault
  <br/>
  <img src="docs/assets/kubevault.svg" alt="Isometric cube inside another one as kubevault logo" height="250">
</h1>

<h4 align="center">kubevault - Kubernetes-based secret management</h4>

<div align="center">

[![License](https://img.shields.io/badge/License-Apache_2.0-blue?logo=git&logoColor=white&logoWidth=20)](LICENSE)
[![Open in GitHub Codespaces](https://img.shields.io/badge/Open_in_Github_Codespace-black?logo=github)](https://github.com/codespaces/new?hide_repo_select=true&repo=832751595)<\br>
[![Crates.io Version](https://img.shields.io/crates/v/kubevault)](https://github.com/chezmoi-sh/kubevault/releases)
[![Crates.io Downloads (recent)](https://img.shields.io/crates/dr/kubevault)](https://crates.io/crates/kubevault)

<a href="#ℹ%EF%B8%8F-about">About</a> ·
<a href="#-getting-started">Getting Started</a> ·
<a href="#%EF%B8%8F-how-it-works-">How it works ?</a> ·
<a href="#%EF%B8%8F-vulnerability-reporting">Vulnerability Reporting</a> ·
<a href="#-license">License</a>

</div>

---

<!-- markdownlint-enable MD033 -->

> [!WARNING]
>
> This project is still in development and is not yet released; take in consideration I will push
> force inside the `main` branch until the first release.

## ℹ️ About

`kubevault` is a homemade alternative to [HashiCorp Vault](https://www.vaultproject.io/) or managed secret management
services like [ASM](https://aws.amazon.com/secrets-manager/) for managing secrets, aiming to have a less complex,
less resource-consuming, but also less secure system.

It relies on Kubernetes' native features for managing secrets (`v1/Secret`), access control (`rbac.authorization.k8s.io/v1/*`),
as well as internal features like audits.

`kubevault` is in reality a simple binary that generates Kubernetes manifests from a configuration directory and lets you
apply them to your Kubernetes cluster in the manner you want _(`kubectl apply`, `GitOps`, ...)_. It also provides some
utilities to manage the secrets and the access control lists.

### 📃 **DISCLAIMER**

> [!WARNING]
>
> **Attention**, the goal of this project is not to provide yet another _shoddy_ alternative to HashiCorp Vault, to be
> THE solution to all secret management problems, or to be THE most secure solution... In fact, this solution
> **IS NOT SECURE** like these services and will not be in the future.
>
> Its purpose is to offer a simple way to manage my secrets in Kubernetes, without having secrets lying around on a
> Post-It or in a text file on the operator computer. It remains "secure" as long as all secrets are encrypted and the
> encryption password or the Kubernetes cluster is not compromised.
>
> Therefore, I do not recommend using this project for production use, but rather if you don't want to bother with
> secret management in Kubernetes _(development clusters or homelab)_.

### 😮 Why create my own _solution_?

This is a rather legitimate question considering the plethora of solutions for managing secrets in Kubernetes. But before
explaining my choice, here is the context in which I found myself when choosing a secret management solution:

1. **I want** my secrets to be securely stored
2. **I want** to have all my secrets in one place
3. **I want** to access my secrets from any Kubernetes cluster
4. **I want** my secrets to be accessible to whoever I want them to be
5. **I do not want** to use more than 1/5GB of RAM
6. **I do not want** to spend time managing the solution
   1. Less than 30 seconds to create/modify/delete a secret and apply it
   2. Less than 10 minutes per month for updates
   3. Less than an hour to rebuild all my data in case of total cluster loss
7. **I do not want** to depend on a third-party service
8. **I would like** to version my secrets
9. **I would like** to audit my secrets

Given these prerequisites, the list was quite short:

- ~~AWS Secrets Manager, Azure Key Vault, Google Secret Manager, HashiCorp Vault Cloud, ...~~ _Third-Party Service_
- ~~1Password, LastPass, Dashlane, ...~~ _Third-Party Service_
- ~~HashiCorp Vault, Open Bao~~ _Quite heavy and complex to manage/maintain_
- ~~Bitwarden, Vaultwarden, ...~~ _No easy-to-use ACL system and no Kubernetes integration_
- There are probably others, but I didn't ~~find~~ look for them

In the end, I didn't find a solution that met all my needs... So I decided to create my own solution.

## 🚀 Getting started

### TLDR;

```shell
# Install kubevault
cargo binstall kubevault

# Create a new vault and your first secrets
kubevault new vault
cat <<EOS > vault/kvstore/my-first-secret
---
# This is my first secret
username: "myusername"
password: "mysecretpassword"
EOS
cat <<EOU > vault/access_control/me
# This is my first user
**
EOU

# Apply the changes
kubectl create namespace vault-kvstore
kubevault generate | kubectl apply -f -
```

### 📦 Installation

The binary name is `kubevault` like the project name and is available for Linux, macOS, and Windows.

However, because it is not something well known, it is not available in the package managers of the different operating
systems. For now, the only ways to install it is via `cargo` or by downloading the binary from the
[releases page](https://github.com/chezmoi-sh/kubevault/releases).

If you have `cargo` installed, you can install it with the following command:

```shell
cargo install kubevault
```

Alternatively, one can use [cargo bininstall](https://github.com/cargo-bins/cargo-binstall) to install the binary
directly from Github:

```shell
cargo binstall kubevault
```

### 🏗️ How to use it ?

The `kubevault` binary is quite simple to use and has a few commands:

- `kubevault new <vault_dir>`: Create a new vault directory structure
- `kubevault generate`: Generate the Kubernetes manifests from the vault directory
  - By default, `kubevault generate` will output the manifests to the standard output. To generate all manifests into a
    directory, use the `--output-dir` option
- `kubevault can-read <user>`: List the secrets a user can read
  - Here is an example of the output:
    ```shell
    KUBEVAULT_DIR=tests/fixtures/vault target/release/kubevault can-read alice --show-only-allowed
    List of secrets accessible by user 'alice':
    ● production-applicationb-postgresql ("production/applicationB/postgresql")
    ● production-applicationb-cloudflare ("production/applicationB/cloudflare")
    ● production-applicationb-openai ("production/applicationB/openai")
    ● production-applicationa-sendgrid ("production/applicationA/sendgrid")
    ● noproduction-users-alice ("noproduction/users/alice")
    ```
- **(TODO)** `kubevault external-secret-store <user>`: Generate the ExternalSecretStore manifest for a user based on the
  current Kubernetes configuration

### ☸ How to integrate it with [External Secrets](https://external-secrets.io/) ?

When creating an user with `kubevault`, an associated secret containing the CA and the token used to connect to the
"vault" Kubernetes cluster is also created. This secret must be extracted in order to be used in the target cluster
to give access to External Secrets.

> [!NOTE]
>
> The following commands assume that the Kubernetes cluster hosting the secrets is accessible through `vault.kubernetes` > _(context `kubevault`)_ and the vault is installed in the `vault-kvstore` namespace.
> `<context>` refers to the context of the target cluster.

```sh
kubectl --context kubevault get secret --namespace vault-kvstore <user>-token -ojson | jq '.type |= "Opaque" | .metadata |= {name: "vault.kubernetes"}' \
| kubectl --context <context> apply --namespace external-secret --filename -
cat <<EOM | kubectl --context <context> apply --filename -
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: vault.kubernetes
spec:
  provider:
    kubernetes:
      remoteNamespace: vault-kvstore
      server:
        url: https://vault.kubernetes:6443
        caProvider:
          type: Secret
          name: vault.kubernetes
          namespace: external-secret
          key: ca.crt
      auth:
        token:
          bearerToken:
            name: vault.kubernetes
            namespace: external-secret
            key: token
EOM
```

You can also use the `kubevault external-secret-store <user>` command to generate the `ClusterSecretStore` manifest for
a user based with the following command:

```shell
kubevault external-secret-store --kubeconfig <kubeconfig> --context vault.kubernetes <user> | kubectl apply --context <context> --filename -
```

## ⚙️ How it works ?

The _solution_ consists of 2 _required_ components:

- [Kubernetes](https://kubernetes.io/) for managing secrets, users, and ACLs
  - [x] **I want** my secrets to be securely stored
    - At least, they are encrypted in the `etcd` database _(or in the SQLite database for [k3s](https://www.k3s.io))_
  - [x] **I want** to have all my secrets in one place
  - [x] **I want** my secrets to be accessible to whoever I want them to be
  - [x] **I do not want** to use more than 500MB of RAM
    - In my case, I will use a Kubernetes cluster that is already running for mission-critical applications[^1] so
      it will cost me nothing
  - [x] **I do not want** to spend time managing the solution
    - As explained above, the time spent managing the solution is already included in the maintenance of the cluster
      uses to host these secrets
  - [x] **I would like** to audit my secrets[^2]
- [External Secrets](https://external-secrets.io/) for accessing secrets from outside
  - [x] **I want** to access my secrets from any Kubernetes cluster

The last point remaining is the versioning of the secrets. For that, I personally use `git` to manage the versions of the
secrets, but feel free to use the solution you prefer, nothing prevents you from using `svn`, `hg`, `bzr`, `fossil`, ...
Of course, in order to keep the secrets secure, I will encrypt them using [`transcrypt`](https://github.com/elasticdog/transcrypt)
before being committed to the repository. However, like for `git`, feel free to use the solution you prefer. Also, because
all secrets are stored in a YAML format, it is possible to use [`SOPS`](https://github.com/getsops/sops) to handle the
encryption features.

Just add a bit of magic and you're done... and this is where `kubevault` comes in. It is a simple binary that generates
Kubernetes manifests from a configuration directory and lets you apply them to your Kubernetes cluster in the manner you
want. However, in order to work, it requires a specific directory architecture.

### 📂 Directory architecture

In order to separate the secrets from the configuration, the following directory structure is used:

```plaintext
└── vault                       # Root vault directory, also called the "vault_dir"
    ├── access_control          # Directory containing users and their ACLs
    │   ├── user1
    │   ├── user2
    │   └── ...
    └── kvstore                 # Directory containing all secrets, in a YAML format
        ├── AAA
        └── BBB
            └── CCC
                └── ...
```

This is the only requirement for the `kubevault` binary to work. The `kvstore` directory contains all the secrets in a
YAML format, and the `access_control` directory contains the users and their ACLs.

#### 🔓 Access Control Lists

The advantage of using this architecture relying on Kubernetes is that there is only one possible action as a user; **read**.
And this greatly simplifies ACL management; it only requires something between a user and the secrets they have access to.
To keep it simple, the ACLs are just a list of `globs` _(based on [crates:glob-match](https://github.com/devongovett/glob-match))_
linked to a user, filtering which file _(or secret)_ they can read or not.

For example, if user `user1` needs access to secret `AAA` and all those in `BBB/CCC` but not `BBB/CCC/EEE`, create the
file `user1` in the `access_control` directory with the following content:

```
# Access control rules for user1
AAA
BBB/CCC/**
!BBB/CCC/EEE
```

> [!CAUTION]
>
> **🟥 CHEATING, REFEREE!**
>
> I have indeed cheated by delegating the write ACL part to the `git` server. However, the most popular `git` servers
> or providers offer the possibility to manage ACLs on repositories.... **So let's take advantage of it** 😄

## 🛡️ Vulnerability reporting

For reporting vulnerabilities, please contact me directly at [xunleii@users.noreply.github.com](mailto:xunleii@users.noreply.github.com).
The PGP public key can be found on my [Keyoxide profile](https://keyoxide.org/0E1D33C2341C0574214913D4E8DC4905AFAEBC64).

## 📜 License

This project is licensed under the [Apache 2.0 License](LICENSE).

[^1]: See [nex·rpi](https://github.com/chezmoi-sh/atlas/tree/poc/pulumi-alt/projects/nex.rpi) for more information

[^2]:
    See [Auditing Kubernetes documentation](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) for more
    information
