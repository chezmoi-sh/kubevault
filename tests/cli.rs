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
use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use std::{fs, process::Command};

#[test]
fn vault_dir_doesnt_exists() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("kubevault")?;

    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: No subcommand provided. Use --help for more information.",
    ));
    Ok(())
}

#[test]
fn generate_with_empty_namespace() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("kubevault")?;

    cmd.arg("generate")
        .arg("--vault-dir")
        .arg("tests/fixtures/vault")
        .arg("--namespace")
        .arg("")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "a value is required for \'--namespace <NAMESPACE>\' but none was supplied",
        ));
    Ok(())
}

#[test]
fn generate_on_stdout() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("kubevault")?;

    let assert = cmd
        .arg("generate")
        .arg("--vault-dir")
        .arg("tests/fixtures/vault")
        .assert()
        .success();

    let expect = fs::read_to_string("tests/fixtures/manifests.yaml")?;
    #[cfg(windows)]
    let expect = expect.replace("\r\n", "\n");
    let actual = std::str::from_utf8(&assert.get_output().stdout)?;
    similar_asserts::assert_eq!(expect, actual);
    Ok(())
}

#[test]
fn generate_on_stdout_with_custom_namespace() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("kubevault")?;

    let assert = cmd
        .arg("generate")
        .arg("--vault-dir")
        .arg("tests/fixtures/vault")
        .arg("--namespace")
        .arg("default")
        .assert()
        .success();

    let expect = fs::read_to_string("tests/fixtures/manifests_default.yaml")?;
    #[cfg(windows)]
    let expect = expect.replace("\r\n", "\n");
    let actual = std::str::from_utf8(&assert.get_output().stdout)?;
    similar_asserts::assert_eq!(expect, actual);
    Ok(())
}

#[test]
fn generate_on_output_dir() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("kubevault")?;
    let output_dir = assert_fs::TempDir::new()?;
    let expect = fs::read_dir("tests/fixtures/manifests")?;

    cmd.arg("generate")
        .arg("--vault-dir")
        .arg("tests/fixtures/vault")
        .arg("--namespace")
        .arg("kubevault-kvstore")
        .arg("--output-dir")
        .arg(output_dir.path())
        .assert()
        .success();

    for entry in expect {
        output_dir
            .child(entry?.file_name())
            .assert(predicate::path::exists());
    }
    Ok(())
}
