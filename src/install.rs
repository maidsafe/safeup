// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::github::GithubReleaseRepository;
use crate::s3::S3AssetRepository;
use color_eyre::{eyre::eyre, Result};
use flate2::read::GzDecoder;
#[cfg(unix)]
use indoc::indoc;
use serde_derive::{Deserialize, Serialize};
use std::env::consts::OS;
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::prelude::*;
use std::io::BufWriter;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tar::Archive;

#[cfg(unix)]
const SET_PATH_FILE_CONTENT: &str = indoc! {r#"
    #!/bin/sh
    case ":${PATH}:" in
        *:"$HOME/.safe/cli":*)
            ;;
        *:"$HOME/.safe/node":*)
            ;;
        *)
            export PATH="$HOME/.safe/cli:$PATH"
            export PATH="$HOME/.safe/node:$PATH"
            ;;
    esac
"#};

#[derive(Clone)]
pub enum AssetType {
    Client,
    Node,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Settings {
    pub safe_path: PathBuf,
    pub safenode_path: PathBuf,
    pub testnet_path: PathBuf,
}

impl Settings {
    pub fn read(settings_file_path: &PathBuf) -> Result<Settings> {
        let settings = if let Ok(mut file) = File::open(settings_file_path) {
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();
            serde_json::from_str(&contents).unwrap_or_else(|_| Settings {
                safe_path: PathBuf::new(),
                safenode_path: PathBuf::new(),
                testnet_path: PathBuf::new(),
            })
        } else {
            Settings {
                safe_path: PathBuf::new(),
                safenode_path: PathBuf::new(),
                testnet_path: PathBuf::new(),
            }
        };
        Ok(settings)
    }

    pub fn save(&self, settings_file_path: &PathBuf) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(settings_file_path)?;
        let json = serde_json::to_string(&self)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }
}

/// Installs either the `safe` or `safenode` binary for the platform specified.
///
/// The latest version is retrieved from Github, then the archive with the binary is downloaded
/// from S3 and extracted to the specified location.
///
/// # Arguments
///
/// * `asset_type` - Either the client or the node.
/// * `release_repository` - The repository for retrieving the latest release from Github.
/// * `asset_repository` - The repository for retrieving the binary archive on S3.
/// * `platform` - The target triple platform of the binary to be installed.
/// * `dest_dir_path` - Path of the directory where the binary will be installed.
/// * `version` - Optionally install a specific version, rather than the latest.
///
/// # Returns
///
/// A tuple of the version number and full path of the installed binary.
pub async fn install_bin(
    asset_type: AssetType,
    release_repository: GithubReleaseRepository,
    asset_repository: S3AssetRepository,
    platform: &str,
    dest_dir_path: PathBuf,
    version: Option<String>,
) -> Result<(String, PathBuf)> {
    let bin_name = get_bin_name(&asset_type);
    println!(
        "Installing {bin_name} for {platform} at {}...",
        dest_dir_path
            .to_str()
            .ok_or_else(|| eyre!("Could not obtain path for shell profile"))?
    );
    std::fs::create_dir_all(&dest_dir_path)?;

    let (asset_name, version) = if let Some(version) = version {
        let asset_name =
            release_repository.get_versioned_asset_name(&asset_type, platform, &version);
        (asset_name, version)
    } else {
        release_repository
            .get_latest_asset_name(asset_type, platform)
            .await?
    };

    let archive_path = dest_dir_path.join(&asset_name);
    asset_repository
        .download_asset(&asset_name, &archive_path)
        .await?;

    let archive_file = File::open(archive_path.clone())?;
    let decoder = GzDecoder::new(archive_file);
    let mut archive = Archive::new(decoder);
    let entries = archive.entries()?;
    for entry_result in entries {
        let mut entry = entry_result?;
        let mut file = BufWriter::new(File::create(dest_dir_path.join(entry.path()?))?);
        std::io::copy(&mut entry, &mut file)?;
    }
    std::fs::remove_file(archive_path)?;

    #[cfg(unix)]
    {
        let extracted_binary_path = dest_dir_path.join(&bin_name);
        let mut perms = extracted_binary_path.metadata()?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(extracted_binary_path, perms)?;
    }

    let bin_path = dest_dir_path.join(bin_name.clone());
    let dest_dir_path = dest_dir_path
        .to_str()
        .ok_or_else(|| eyre!("Could not obtain path for shell profile"))?;
    println!("{bin_name} {version} is now available at {dest_dir_path}/{bin_name}");
    Ok((version, bin_path))
}

#[cfg(unix)]
pub async fn configure_shell_profile(
    shell_profile_file_path: &PathBuf,
    path_config_file_path: &PathBuf,
) -> Result<()> {
    let mut path_config_file = File::create(path_config_file_path)?;
    path_config_file.write_all(SET_PATH_FILE_CONTENT.as_bytes())?;
    let path_config_file_path = path_config_file_path
        .to_str()
        .ok_or_else(|| eyre!("Could not obtain path for path config file"))?;

    let shell_profile = std::fs::read_to_string(shell_profile_file_path)?;
    let count = shell_profile
        .matches(&format!("source {}", path_config_file_path))
        .count();
    if count == 0 {
        let mut shell_profile_file = std::fs::OpenOptions::new()
            .append(true)
            .open(shell_profile_file_path)?;
        let content = format!("source {}", path_config_file_path);
        shell_profile_file.write_all(content.as_bytes())?;
        println!(
            "Modified shell profile at {}",
            shell_profile_file_path
                .to_str()
                .ok_or_else(|| eyre!("Could not obtain path for shell profile"))?
        );
        println!(
            "To make safe available in this session run 'source {}'",
            path_config_file_path
        );
    }

    Ok(())
}

#[cfg(windows)]
pub async fn configure_shell_profile(
    _shell_profile_file_path: &PathBuf,
    _path_config_file_path: &PathBuf,
) -> Result<()> {
    Ok(())
}

fn get_bin_name(asset_type: &AssetType) -> String {
    let mut bin_name = match asset_type {
        AssetType::Client => "safe".to_string(),
        AssetType::Node => "safenode".to_string(),
    };
    if OS == "windows" {
        bin_name.push_str(".exe");
    }
    bin_name
}

/// The `install_bin` tests unfortunately require setup that leads to a lot of duplication.
///
/// For that reason, all the code paths won't be tested. Technically, there should be other test
/// cases for using `AssetType::Node`, but the difference between each type is small enough such
/// that it's not worth the duplication of setup.
///
/// The node install will also be tested during the CI process, so we'll get coverage there.
#[cfg(test)]
mod test {
    #[cfg(unix)]
    use super::{configure_shell_profile, install_bin, AssetType, Settings, SET_PATH_FILE_CONTENT};
    #[cfg(windows)]
    use super::{install_bin, AssetType};
    use crate::github::GithubReleaseRepository;
    use crate::s3::S3AssetRepository;
    use assert_fs::prelude::*;
    use color_eyre::Result;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use httpmock::prelude::*;
    use std::fs::File;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    #[tokio::test]
    async fn install_bin_should_install_the_latest_version() -> Result<()> {
        let github_server = MockServer::start();
        let response_body = std::fs::read_to_string(
            Path::new("resources").join("latest_release_response_body.json"),
        )?;

        let latest_release_mock = github_server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/latest");
            then.status(200)
                .header("server", "Github.com")
                .body(response_body);
        });

        let tmp_data_path = assert_fs::TempDir::new()?;
        let extract_dir = tmp_data_path.child("extract");
        extract_dir.create_dir_all()?;
        let extracted_safe = extract_dir.child("safe");

        let safe_archive = tmp_data_path.child("safe.tar.gz");
        let downloaded_safe_archive =
            extract_dir.child("safe-0.74.2-x86_64-unknown-linux-musl.tar.gz");
        let fake_safe_bin = tmp_data_path.child("safe");
        fake_safe_bin.write_binary(b"fake code")?;

        let mut fake_safe_bin_file = File::open(fake_safe_bin.path())?;
        let gz_encoder = GzEncoder::new(File::create(safe_archive.path())?, Compression::default());
        let mut builder = tar::Builder::new(gz_encoder);
        builder.append_file("safe", &mut fake_safe_bin_file)?;
        builder.into_inner()?;
        let safe_archive_metadata = std::fs::metadata(safe_archive.path())?;

        let asset_server = MockServer::start();
        let download_asset_mock = asset_server.mock(|when, then| {
            when.method(GET)
                .path("/safe-0.74.2-x86_64-unknown-linux-musl.tar.gz");
            then.status(200)
                .header("Content-Length", safe_archive_metadata.len().to_string())
                .header("Content-Type", "application/gzip")
                .body_from_file(safe_archive.path().to_str().unwrap());
        });

        let asset_repository = S3AssetRepository::new(&asset_server.base_url());
        let release_repository =
            GithubReleaseRepository::new(&github_server.base_url(), "maidsafe", "safe_network");
        let (version, bin_path) = install_bin(
            AssetType::Client,
            release_repository,
            asset_repository,
            "x86_64-unknown-linux-musl",
            extract_dir.path().to_path_buf(),
            None,
        )
        .await?;

        download_asset_mock.assert();
        latest_release_mock.assert();
        extracted_safe.assert(predicates::path::is_file());
        downloaded_safe_archive.assert(predicates::path::missing());
        assert_eq!(version, "0.74.2");
        assert_eq!(bin_path, extracted_safe.to_path_buf());

        #[cfg(unix)]
        {
            let extracted_safe_metadata = std::fs::metadata(extracted_safe.path())?;
            assert_eq!(
                (extracted_safe_metadata.permissions().mode() & 0o777),
                0o755
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn install_bin_when_parent_dirs_in_dest_path_do_not_exist_should_install_the_latest_version(
    ) -> Result<()> {
        let github_server = MockServer::start();
        let response_body = std::fs::read_to_string(
            Path::new("resources").join("latest_release_response_body.json"),
        )?;
        let latest_release_mock = github_server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/latest");
            then.status(200)
                .header("server", "Github.com")
                .body(response_body);
        });

        let tmp_data_path = assert_fs::TempDir::new()?;
        let extract_dir = tmp_data_path.child("extract/when/parents/do/not/exist");
        let extracted_safe = extract_dir.child("safe");

        let safe_archive = tmp_data_path.child("safe.tar.gz");
        let downloaded_safe_archive =
            extract_dir.child("safe-0.74.2-x86_64-unknown-linux-musl.tar.gz");
        let fake_safe_bin = tmp_data_path.child("safe");
        fake_safe_bin.write_binary(b"fake code")?;

        let mut fake_safe_bin_file = File::open(fake_safe_bin.path())?;
        let gz_encoder = GzEncoder::new(File::create(safe_archive.path())?, Compression::default());
        let mut builder = tar::Builder::new(gz_encoder);
        builder.append_file("safe", &mut fake_safe_bin_file)?;
        builder.into_inner()?;
        let safe_archive_metadata = std::fs::metadata(safe_archive.path())?;

        let asset_server = MockServer::start();
        let download_asset_mock = asset_server.mock(|when, then| {
            when.method(GET)
                .path("/safe-0.74.2-x86_64-unknown-linux-musl.tar.gz");
            then.status(200)
                .header("Content-Length", safe_archive_metadata.len().to_string())
                .header("Content-Type", "application/gzip")
                .body_from_file(safe_archive.path().to_str().unwrap());
        });

        let asset_repository = S3AssetRepository::new(&asset_server.base_url());
        let release_repository =
            GithubReleaseRepository::new(&github_server.base_url(), "maidsafe", "safe_network");
        let (version, bin_path) = install_bin(
            AssetType::Client,
            release_repository,
            asset_repository,
            "x86_64-unknown-linux-musl",
            extract_dir.path().to_path_buf(),
            None,
        )
        .await?;

        download_asset_mock.assert();
        latest_release_mock.assert();
        extracted_safe.assert(predicates::path::is_file());
        downloaded_safe_archive.assert(predicates::path::missing());
        assert_eq!(version, "0.74.2");
        assert_eq!(bin_path, extracted_safe.to_path_buf());
        Ok(())
    }

    /// For installing a specific version, no request is made to the Github API, so the mocked
    /// Github server is not necessary.
    #[tokio::test]
    async fn install_bin_should_install_a_specific_version() -> Result<()> {
        let specific_version = "0.74.5";
        let tmp_data_path = assert_fs::TempDir::new()?;
        let extract_dir = tmp_data_path.child("extract");
        extract_dir.create_dir_all()?;
        let extracted_safe = extract_dir.child("safe");

        let safe_archive = tmp_data_path.child("safe.tar.gz");
        let downloaded_safe_archive = extract_dir.child(format!(
            "safe-{specific_version}-x86_64-unknown-linux-musl.tar.gz"
        ));
        let fake_safe_bin = tmp_data_path.child("safe");
        fake_safe_bin.write_binary(b"fake code")?;

        let mut fake_safe_bin_file = File::open(fake_safe_bin.path())?;
        let gz_encoder = GzEncoder::new(File::create(safe_archive.path())?, Compression::default());
        let mut builder = tar::Builder::new(gz_encoder);
        builder.append_file("safe", &mut fake_safe_bin_file)?;
        builder.into_inner()?;
        let safe_archive_metadata = std::fs::metadata(safe_archive.path())?;

        let asset_server = MockServer::start();
        let download_asset_mock = asset_server.mock(|when, then| {
            when.method(GET).path(format!(
                "/safe-{specific_version}-x86_64-unknown-linux-musl.tar.gz"
            ));
            then.status(200)
                .header("Content-Length", safe_archive_metadata.len().to_string())
                .header("Content-Type", "application/gzip")
                .body_from_file(safe_archive.path().to_str().unwrap());
        });

        let asset_repository = S3AssetRepository::new(&asset_server.base_url());
        let release_repository =
            GithubReleaseRepository::new("localhost", "maidsafe", "safe_network");
        let (version, bin_path) = install_bin(
            AssetType::Client,
            release_repository,
            asset_repository,
            "x86_64-unknown-linux-musl",
            extract_dir.path().to_path_buf(),
            Some(specific_version.to_string()),
        )
        .await?;

        download_asset_mock.assert();
        extracted_safe.assert(predicates::path::is_file());
        downloaded_safe_archive.assert(predicates::path::missing());
        assert_eq!(version, specific_version);
        assert_eq!(bin_path, extracted_safe.to_path_buf());

        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn configure_shell_profile_should_put_client_and_node_on_path() -> Result<()> {
        let tmp_data_path = assert_fs::TempDir::new()?;
        let bashrc_file = tmp_data_path.child(".bashrc");
        bashrc_file.write_file(Path::new("resources/default_bashrc"))?;
        let path_config_file = tmp_data_path.child("env");

        let result = configure_shell_profile(
            &bashrc_file.path().to_path_buf(),
            &path_config_file.path().to_path_buf(),
        )
        .await;

        assert!(result.is_ok());
        path_config_file.assert(predicates::path::is_file());
        let path_config_file_contents = std::fs::read_to_string(path_config_file.path())?;
        assert_eq!(SET_PATH_FILE_CONTENT, path_config_file_contents);

        let bash_profile_contents = std::fs::read_to_string(bashrc_file.path())?;
        assert!(bash_profile_contents.ends_with(&format!(
            "source {}",
            path_config_file.path().to_str().unwrap()
        )));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn configure_shell_profile_should_not_put_duplicate_entries_in_profile() -> Result<()> {
        let tmp_data_path = assert_fs::TempDir::new()?;
        let bashrc_file = tmp_data_path.child(".bashrc");
        bashrc_file.write_file(Path::new("resources/default_bashrc"))?;
        let path_config_file = tmp_data_path.child("env");

        let result = configure_shell_profile(
            &bashrc_file.path().to_path_buf(),
            &path_config_file.path().to_path_buf(),
        )
        .await;
        assert!(result.is_ok());

        let result = configure_shell_profile(
            &bashrc_file.path().to_path_buf(),
            &path_config_file.path().to_path_buf(),
        )
        .await;
        assert!(result.is_ok());

        let bash_profile_contents = std::fs::read_to_string(bashrc_file.path())?;
        assert_eq!(
            1,
            bash_profile_contents
                .matches(&format!(
                    "source {}",
                    path_config_file.path().to_str().unwrap()
                ))
                .count()
        );

        Ok(())
    }

    #[tokio::test]
    async fn save_should_write_new_settings_when_settings_file_does_not_exist() -> Result<()> {
        let tmp_data_path = assert_fs::TempDir::new()?;
        let settings_file = tmp_data_path.child("safeup.json");
        let safe_bin_file = tmp_data_path.child("safe");
        safe_bin_file.write_binary(b"fake safe code")?;
        let safenode_bin_file = tmp_data_path.child("safenode");
        safenode_bin_file.write_binary(b"fake safenode code")?;
        let testnet_bin_file = tmp_data_path.child("testnet");
        testnet_bin_file.write_binary(b"fake testnet code")?;

        let settings = Settings {
            safe_path: safe_bin_file.to_path_buf(),
            safenode_path: safenode_bin_file.to_path_buf(),
            testnet_path: testnet_bin_file.to_path_buf(),
        };

        settings.save(&settings_file.to_path_buf())?;

        settings_file.assert(predicates::path::is_file());
        let settings = Settings::read(&settings_file.to_path_buf())?;
        assert_eq!(settings.safe_path, safe_bin_file.to_path_buf());
        assert_eq!(settings.safenode_path, safenode_bin_file.to_path_buf());
        assert_eq!(settings.testnet_path, testnet_bin_file.to_path_buf());
        Ok(())
    }

    #[tokio::test]
    async fn save_should_write_updated_settings() -> Result<()> {
        let tmp_data_path = assert_fs::TempDir::new()?;
        let settings_file = tmp_data_path.child("safeup.json");
        settings_file.write_str(
            r#"
        {
          "safe_path": "/usr/local/bin/safe",
          "safenode_path": "/usr/local/bin/safenode",
          "testnet_path": "/usr/local/bin/testnet"
        }
        "#,
        )?;

        let safenode_bin_file = tmp_data_path.child("safenode");
        safenode_bin_file.write_binary(b"fake safenode code")?;

        let mut settings = Settings::read(&settings_file.to_path_buf())?;
        settings.safenode_path = safenode_bin_file.to_path_buf();

        settings.save(&settings_file.to_path_buf())?;

        settings_file.assert(predicates::path::is_file());
        let settings = Settings::read(&settings_file.to_path_buf())?;
        assert_eq!(settings.safe_path, PathBuf::from("/usr/local/bin/safe"));
        assert_eq!(settings.safenode_path, safenode_bin_file.to_path_buf());
        assert_eq!(
            settings.testnet_path,
            PathBuf::from("/usr/local/bin/testnet")
        );
        Ok(())
    }
}
