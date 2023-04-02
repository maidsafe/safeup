// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::github::GithubReleaseRepository;
use crate::s3::S3AssetRepository;
#[cfg(windows)]
use color_eyre::{eyre::eyre, Help, Result};
#[cfg(unix)]
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
#[cfg(windows)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tar::Archive;
#[cfg(windows)]
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE};
#[cfg(windows)]
use winreg::RegKey;

#[cfg(windows)]
const VCPP_REDIST_URL: &str = "https://download.microsoft.com/download/9/3/F/93FCF1E7-E6A4-478B-96E7-D4B285925B00/vc_redist.x64.exe";

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
    Testnet,
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
            file.read_to_string(&mut contents)?;
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
        let parent_dir = settings_file_path
            .parent()
            .ok_or_else(|| eyre!("Could not obtain parent"))?;
        std::fs::create_dir_all(parent_dir)?;
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

#[cfg(unix)]
pub fn check_prerequisites() -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn check_prerequisites() -> Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let uninstall_key_path = "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    let uninstall_key = hklm.open_subkey_with_flags(uninstall_key_path, KEY_READ)?;
    for result in uninstall_key.enum_keys().map(|res| res.unwrap()) {
        let subkey = match uninstall_key.open_subkey_with_flags(&result, KEY_READ) {
            Ok(key) => key,
            Err(_) => continue,
        };

        if let Ok(display_name) = subkey.get_value::<String, _>("DisplayName") {
            if display_name.starts_with("Microsoft Visual C++") {
                return Ok(());
            }
        }
    }

    Err(
        eyre!("Failed to find installation of the Microsoft Visual C++ Redistributable")
            .suggestion(format!(
                "Please download and install it from {VCPP_REDIST_URL} \
                    then proceed with the installation."
            )),
    )
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
    let full_path = bin_path
        .to_str()
        .ok_or_else(|| eyre!("Could not obtain path for shell profile"))?;
    println!("{bin_name} {version} is now available at {full_path}");
    Ok((version, bin_path))
}

#[cfg(unix)]
pub async fn configure_shell_profile(
    _dest_dir_path: &Path,
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
    dest_dir_path: &PathBuf,
    _shell_profile_file_path: &Path,
    _path_config_file_path: &Path,
) -> Result<()> {
    let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey("Environment")?;
    let path_var: String = key.get_value("Path")?;
    let paths: Vec<PathBuf> = std::env::split_paths(&path_var).collect();

    if !paths.contains(dest_dir_path) {
        let mut new_paths = paths;
        new_paths.push(dest_dir_path.clone());

        let new_path_var = std::env::join_paths(new_paths.iter())?;
        let new_path_var_str = new_path_var
            .to_str()
            .ok_or_else(|| eyre!("Could not obtain path"))?;
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Environment", KEY_SET_VALUE)?;
        key.set_value("PATH", &new_path_var_str)?;

        let install_path = dest_dir_path
            .to_str()
            .ok_or_else(|| eyre!("Could not obtain path for shell profile"))?;
        println!("Adding {install_path} to the user Path environment variable");
        println!("A new shell session will be required for this to take effect");
    }
    Ok(())
}

fn get_bin_name(asset_type: &AssetType) -> String {
    let mut bin_name = match asset_type {
        AssetType::Client => "safe".to_string(),
        AssetType::Node => "safenode".to_string(),
        AssetType::Testnet => "testnet".to_string(),
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
    use super::{install_bin, AssetType, Settings};
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

    /// These may seem pointless, but they are useful for when the tests run on different
    /// platforms.
    #[cfg(unix)]
    const SAFE_BIN_NAME: &str = "safe";
    #[cfg(windows)]
    const SAFE_BIN_NAME: &str = "safe.exe";
    #[cfg(unix)]
    const SAFENODE_BIN_NAME: &str = "safenode";
    #[cfg(windows)]
    const SAFENODE_BIN_NAME: &str = "safenode.exe";
    #[cfg(unix)]
    const PLATFORM: &str = "x86_64-unknown-linux-musl";
    #[cfg(windows)]
    const PLATFORM: &str = "x86_64-pc-windows-msvc";

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
        let extracted_safe_bin = extract_dir.child(SAFE_BIN_NAME);

        let safe_archive = tmp_data_path.child("safe.tar.gz");
        let downloaded_safe_archive = extract_dir.child(format!("safe-0.74.2-{}.tar.gz", PLATFORM));
        let fake_safe_bin = tmp_data_path.child(SAFE_BIN_NAME);
        fake_safe_bin.write_binary(b"fake code")?;

        let mut fake_safe_bin_file = File::open(fake_safe_bin.path())?;
        let gz_encoder = GzEncoder::new(File::create(safe_archive.path())?, Compression::default());
        let mut builder = tar::Builder::new(gz_encoder);
        builder.append_file(SAFE_BIN_NAME, &mut fake_safe_bin_file)?;
        builder.into_inner()?;
        let safe_archive_metadata = std::fs::metadata(safe_archive.path())?;

        let asset_server = MockServer::start();
        let download_asset_mock = asset_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/safe-0.74.2-{}.tar.gz", PLATFORM));
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
            PLATFORM,
            extract_dir.path().to_path_buf(),
            None,
        )
        .await?;

        download_asset_mock.assert();
        latest_release_mock.assert();
        extracted_safe_bin.assert(predicates::path::is_file());
        downloaded_safe_archive.assert(predicates::path::missing());
        assert_eq!(version, "0.74.2");
        assert_eq!(bin_path, extracted_safe_bin.to_path_buf());

        #[cfg(unix)]
        {
            let extracted_safe_metadata = std::fs::metadata(extracted_safe_bin.path())?;
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
        let extract_dir = tmp_data_path.child(
            PathBuf::from("extract")
                .join("when")
                .join("parents")
                .join("do")
                .join("not")
                .join("exist"),
        );
        let extracted_safe_bin = extract_dir.child(SAFE_BIN_NAME);

        let safe_archive = tmp_data_path.child("safe.tar.gz");
        let downloaded_safe_archive = extract_dir.child(format!("safe-0.74.2-{}.tar.gz", PLATFORM));
        let fake_safe_bin = tmp_data_path.child(SAFE_BIN_NAME);
        fake_safe_bin.write_binary(b"fake code")?;

        let mut fake_safe_bin_file = File::open(fake_safe_bin.path())?;
        let gz_encoder = GzEncoder::new(File::create(safe_archive.path())?, Compression::default());
        let mut builder = tar::Builder::new(gz_encoder);
        builder.append_file(SAFE_BIN_NAME, &mut fake_safe_bin_file)?;
        builder.into_inner()?;
        let safe_archive_metadata = std::fs::metadata(safe_archive.path())?;

        let asset_server = MockServer::start();
        let download_asset_mock = asset_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/safe-0.74.2-{}.tar.gz", PLATFORM));
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
            PLATFORM,
            extract_dir.path().to_path_buf(),
            None,
        )
        .await?;

        download_asset_mock.assert();
        latest_release_mock.assert();
        extracted_safe_bin.assert(predicates::path::is_file());
        downloaded_safe_archive.assert(predicates::path::missing());
        assert_eq!(version, "0.74.2");
        assert_eq!(bin_path, extracted_safe_bin.to_path_buf());
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
        let extracted_safe_bin = extract_dir.child(SAFE_BIN_NAME);

        let safe_archive = tmp_data_path.child("safe.tar.gz");
        let downloaded_safe_archive =
            extract_dir.child(format!("safe-{specific_version}-{}.tar.gz", PLATFORM));
        let fake_safe_bin = tmp_data_path.child(SAFE_BIN_NAME);
        fake_safe_bin.write_binary(b"fake code")?;

        let mut fake_safe_bin_file = File::open(fake_safe_bin.path())?;
        let gz_encoder = GzEncoder::new(File::create(safe_archive.path())?, Compression::default());
        let mut builder = tar::Builder::new(gz_encoder);
        builder.append_file(SAFE_BIN_NAME, &mut fake_safe_bin_file)?;
        builder.into_inner()?;
        let safe_archive_metadata = std::fs::metadata(safe_archive.path())?;

        let asset_server = MockServer::start();
        let download_asset_mock = asset_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/safe-{specific_version}-{}.tar.gz", PLATFORM));
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
            PLATFORM,
            extract_dir.path().to_path_buf(),
            Some(specific_version.to_string()),
        )
        .await?;

        download_asset_mock.assert();
        extracted_safe_bin.assert(predicates::path::is_file());
        downloaded_safe_archive.assert(predicates::path::missing());
        assert_eq!(version, specific_version);
        assert_eq!(bin_path, extracted_safe_bin.to_path_buf());

        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn configure_shell_profile_should_put_client_and_node_on_path() -> Result<()> {
        let tmp_data_path = assert_fs::TempDir::new()?;
        // The destination directory doesn't actually get used on Linux/macOS, but it needs
        // to be provided anyway.
        let dest_dir = tmp_data_path.child("dest");
        let bashrc_file = tmp_data_path.child(".bashrc");
        bashrc_file.write_file(Path::new("resources/default_bashrc"))?;
        let path_config_file = tmp_data_path.child("env");

        let result = configure_shell_profile(
            dest_dir.path(),
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
        // The destination directory doesn't actually get used on Linux/macOS, but it needs
        // to be provided anyway.
        let dest_dir = tmp_data_path.child("dest");
        let bashrc_file = tmp_data_path.child(".bashrc");
        bashrc_file.write_file(Path::new("resources/default_bashrc"))?;
        let path_config_file = tmp_data_path.child("env");

        let result = configure_shell_profile(
            dest_dir.path(),
            &bashrc_file.path().to_path_buf(),
            &path_config_file.path().to_path_buf(),
        )
        .await;
        assert!(result.is_ok());

        let result = configure_shell_profile(
            dest_dir.path(),
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
        let safe_bin_file = tmp_data_path.child(SAFE_BIN_NAME);
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
    async fn save_should_write_new_settings_when_parent_dirs_do_not_exist() -> Result<()> {
        let tmp_data_path = assert_fs::TempDir::new()?;
        let settings_file = tmp_data_path.child(
            PathBuf::from("some")
                .join("parent")
                .join("dirs")
                .join("safeup.json"),
        );
        let safe_bin_file = tmp_data_path.child(SAFE_BIN_NAME);
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

        let safenode_bin_file = tmp_data_path.child(SAFENODE_BIN_NAME);
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
