// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(windows)]
use color_eyre::{eyre::eyre, Help, Result};
#[cfg(unix)]
use color_eyre::{eyre::eyre, Result};
use indicatif::{ProgressBar, ProgressStyle};
#[cfg(unix)]
use indoc::indoc;
use semver::Version;
use serde::de::Visitor;
use serde::{Deserializer, Serializer};
use serde_derive::{Deserialize, Serialize};
use sn_releases::{get_running_platform, ArchiveType, ReleaseType, SafeReleaseRepoActions};
use std::env::consts::OS;
use std::fmt;
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::prelude::*;
#[cfg(windows)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
        *:"$HOME/.local/bin":*)
            ;;
        *)
            export PATH="$HOME/.local/bin:$PATH"
            ;;
    esac
"#};

#[derive(Clone, Eq, Hash, PartialEq)]
pub enum AssetType {
    Client,
    Node,
    NodeManager,
}

impl AssetType {
    pub fn variants() -> Vec<AssetType> {
        vec![AssetType::Client, AssetType::Node, AssetType::NodeManager]
    }

    pub fn get_release_type(&self) -> ReleaseType {
        match self {
            AssetType::Client => ReleaseType::Autonomi,
            AssetType::Node => ReleaseType::Safenode,
            AssetType::NodeManager => ReleaseType::SafenodeManager,
        }
    }
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            AssetType::Client => write!(f, "autonomi"),
            AssetType::Node => write!(f, "safenode"),
            AssetType::NodeManager => write!(f, "safenode-manager"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    pub autonomi_path: Option<PathBuf>,
    #[serde(
        serialize_with = "serialize_version",
        deserialize_with = "deserialize_version"
    )]
    pub autonomi_version: Option<Version>,
    pub safenode_path: Option<PathBuf>,
    #[serde(
        serialize_with = "serialize_version",
        deserialize_with = "deserialize_version"
    )]
    pub safenode_version: Option<Version>,
    pub safenode_manager_path: Option<PathBuf>,
    #[serde(
        serialize_with = "serialize_version",
        deserialize_with = "deserialize_version"
    )]
    pub safenode_manager_version: Option<Version>,
}

fn serialize_version<S>(version: &Option<Version>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match version {
        Some(v) => serializer.serialize_some(&v.to_string()),
        None => serializer.serialize_none(),
    }
}

fn deserialize_version<'de, D>(deserializer: D) -> Result<Option<Version>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_option(VersionOptionVisitor)
}

struct VersionOptionVisitor;

impl<'de> Visitor<'de> for VersionOptionVisitor {
    type Value = Option<Version>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an option of a string representing a semver version")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(VersionVisitor).map(Some)
    }
}

struct VersionVisitor;

impl<'de> Visitor<'de> for VersionVisitor {
    type Value = Version;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string representing a semver version")
    }

    fn visit_str<E>(self, value: &str) -> Result<Version, E>
    where
        E: serde::de::Error,
    {
        value.parse().map_err(serde::de::Error::custom)
    }
}

impl Settings {
    pub fn read(settings_file_path: &PathBuf) -> Result<Settings> {
        let settings = if let Ok(mut file) = File::open(settings_file_path) {
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            serde_json::from_str(&contents).unwrap_or_else(|_| Settings {
                autonomi_path: None,
                autonomi_version: None,
                safenode_path: None,
                safenode_version: None,
                safenode_manager_path: None,
                safenode_manager_version: None,
            })
        } else {
            Settings {
                autonomi_path: None,
                autonomi_version: None,
                safenode_path: None,
                safenode_version: None,
                safenode_manager_path: None,
                safenode_manager_version: None,
            }
        };
        Ok(settings)
    }

    pub fn get_install_details(&self, asset_type: &AssetType) -> Option<(PathBuf, Version)> {
        match asset_type {
            AssetType::Client => {
                if self.autonomi_path.is_some() {
                    let path = self.autonomi_path.as_ref().unwrap();
                    let version = self.autonomi_version.as_ref().unwrap();
                    return Some((path.clone(), version.clone()));
                }
                None
            }
            AssetType::Node => {
                if self.safenode_path.is_some() {
                    let path = self.safenode_path.as_ref().unwrap();
                    let version = self.safenode_version.as_ref().unwrap();
                    return Some((path.clone(), version.clone()));
                }
                None
            }
            AssetType::NodeManager => {
                if self.safenode_manager_path.is_some() {
                    let path = self.safenode_manager_path.as_ref().unwrap();
                    let version = self.safenode_manager_version.as_ref().unwrap();
                    return Some((path.clone(), version.clone()));
                }
                None
            }
        }
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
    release_repo: Box<dyn SafeReleaseRepoActions>,
    platform: &str,
    dest_dir_path: PathBuf,
    version: Option<Version>,
) -> Result<(Version, PathBuf)> {
    let bin_name = get_bin_name(&asset_type);
    println!(
        "Installing {bin_name} for {platform} at {}...",
        dest_dir_path
            .to_str()
            .ok_or_else(|| eyre!("Could not obtain path for shell profile"))?
    );
    std::fs::create_dir_all(&dest_dir_path)?;

    let pb = Arc::new(ProgressBar::new(0));
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));
    let pb_clone = pb.clone();
    let callback: Box<dyn Fn(u64, u64) + Send + Sync> = Box::new(move |downloaded, total| {
        pb_clone.set_length(total);
        pb_clone.set_position(downloaded);
    });

    let version = if let Some(version) = version {
        version
    } else {
        println!("Retrieving latest version for {asset_type}...");
        release_repo
            .get_latest_version(&asset_type.get_release_type())
            .await?
    };

    let temp_dir = tempfile::tempdir()?;

    println!("Installing {asset_type} version {version}...");
    let archive_path = release_repo
        .download_release_from_s3(
            &asset_type.get_release_type(),
            &version,
            &get_running_platform()?,
            &ArchiveType::TarGz,
            temp_dir.path(),
            &callback,
        )
        .await?;
    pb.finish_with_message("Download complete");

    let bin_path = release_repo.extract_release_archive(&archive_path, &dest_dir_path)?;
    #[cfg(unix)]
    {
        let mut perms = bin_path.metadata()?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(bin_path.clone(), perms)?;
    }

    println!(
        "{bin_name} {version} is now available at {}",
        bin_path.to_string_lossy()
    );

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
        println!("Alternatively you can start a new session");
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
        AssetType::Client => "autonomi".to_string(),
        AssetType::Node => "safenode".to_string(),
        AssetType::NodeManager => "safenode-manager".to_string(),
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
    use assert_fs::prelude::*;
    use async_trait::async_trait;
    use color_eyre::Result;
    use mockall::mock;
    use mockall::predicate::*;
    use mockall::Sequence;
    use semver::Version;
    use sn_releases::{
        ArchiveType, Platform, ProgressCallback, ReleaseType, Result as SnReleaseResult,
        SafeReleaseRepoActions,
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// These may seem pointless, but they are useful for when the tests run on different
    /// platforms.
    #[cfg(unix)]
    const AUTONOMI_BIN_NAME: &str = "autonomi";
    #[cfg(windows)]
    const AUTONOMI_BIN_NAME: &str = "autonomi.exe";
    #[cfg(unix)]
    const PLATFORM: &str = "x86_64-unknown-linux-musl";
    #[cfg(windows)]
    const PLATFORM: &str = "x86_64-pc-windows-msvc";

    mock! {
        pub SafeReleaseRepository {}
        #[async_trait]
        impl SafeReleaseRepoActions for SafeReleaseRepository {
            async fn get_latest_version(&self, release_type: &ReleaseType) -> SnReleaseResult<Version>;
            async fn download_release_from_s3(
                &self,
                release_type: &ReleaseType,
                version: &Version,
                platform: &Platform,
                archive_type: &ArchiveType,
                download_dir: &Path,
                callback: &ProgressCallback
            ) -> SnReleaseResult<PathBuf>;
            async fn download_release(
                &self,
                url: &str,
                dest_dir_path: &Path,
                callback: &ProgressCallback,
            ) -> SnReleaseResult<PathBuf>;
            async fn download_winsw(&self, dest_path: &Path, callback: &ProgressCallback) -> SnReleaseResult<()>;
            fn extract_release_archive(&self, archive_path: &Path, extract_dir: &Path) -> SnReleaseResult<PathBuf>;
        }
    }

    #[tokio::test]
    async fn install_bin_should_install_the_latest_version() -> Result<()> {
        let latest_version = Version::new(0, 86, 55);
        let latest_version_clone1 = latest_version.clone();
        let latest_version_clone2 = latest_version.clone();
        let temp_dir = assert_fs::TempDir::new()?;

        let install_dir = temp_dir.child("install");
        let installed_autonomi = install_dir.child("autonomi");
        // By creating this file we are 'pretending' that it was extracted to the specified
        // location. It's done so we can assert that the file is made executable.
        installed_autonomi.write_binary(b"fake autonomi bin")?;

        let mut mock_release_repo = MockSafeReleaseRepository::new();
        let mut seq = Sequence::new();
        mock_release_repo
            .expect_get_latest_version()
            .times(1)
            .returning(move |_| Ok(latest_version_clone1.clone()))
            .in_sequence(&mut seq);

        mock_release_repo
            .expect_download_release_from_s3()
            .with(
                eq(&ReleaseType::Autonomi),
                eq(latest_version.clone()),
                always(), // Varies per platform
                eq(&ArchiveType::TarGz),
                always(), // Temporary directory which doesn't really matter
                always(), // Callback for progress bar which also doesn't matter
            )
            .times(1)
            .returning(move |_, _, _, _, _, _| {
                Ok(PathBuf::from(format!(
                    "/tmp/autonomi-{}-x86_64-unknown-linux-musl.tar.gz",
                    latest_version_clone2
                )))
            })
            .in_sequence(&mut seq);

        let mut install_dir_path_clone = install_dir.to_path_buf().clone();
        install_dir_path_clone.push("autonomi");
        mock_release_repo
            .expect_extract_release_archive()
            .with(
                eq(PathBuf::from(format!(
                    "/tmp/autonomi-{}-x86_64-unknown-linux-musl.tar.gz",
                    latest_version.clone()
                ))),
                always(), // We will extract to a temporary directory
            )
            .times(1)
            .returning(move |_, _| Ok(install_dir_path_clone.clone()))
            .in_sequence(&mut seq);

        let (version, bin_path) = install_bin(
            AssetType::Client,
            Box::new(mock_release_repo),
            PLATFORM,
            install_dir.path().to_path_buf(),
            None,
        )
        .await?;

        assert_eq!(version, Version::new(0, 86, 55));
        assert_eq!(bin_path, installed_autonomi.to_path_buf());

        #[cfg(unix)]
        {
            let extracted_autonomi_metadata = std::fs::metadata(installed_autonomi.path())?;
            assert_eq!(
                (extracted_autonomi_metadata.permissions().mode() & 0o777),
                0o755
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn install_bin_when_parent_dirs_in_dest_path_do_not_exist_should_install_the_latest_version(
    ) -> Result<()> {
        let latest_version = Version::new(0, 86, 55);
        let latest_version_clone1 = latest_version.clone();
        let latest_version_clone2 = latest_version.clone();
        let temp_dir = assert_fs::TempDir::new()?;

        let install_dir = temp_dir.child("install/using/many/paths");
        let installed_autonomi = install_dir.child("autonomi");
        // By creating this file we are 'pretending' that it was extracted to the specified
        // location. It's done so we can assert that the file is made executable.
        installed_autonomi.write_binary(b"fake autonomi bin")?;

        let mut mock_release_repo = MockSafeReleaseRepository::new();
        let mut seq = Sequence::new();
        mock_release_repo
            .expect_get_latest_version()
            .times(1)
            .returning(move |_| Ok(latest_version_clone1.clone()))
            .in_sequence(&mut seq);

        mock_release_repo
            .expect_download_release_from_s3()
            .with(
                eq(&ReleaseType::Autonomi),
                eq(latest_version.clone()),
                always(), // Varies per platform
                eq(&ArchiveType::TarGz),
                always(), // Temporary directory which doesn't really matter
                always(), // Callback for progress bar which also doesn't matter
            )
            .times(1)
            .returning(move |_, _, _, _, _, _| {
                Ok(PathBuf::from(format!(
                    "/tmp/autonomi-{}-x86_64-unknown-linux-musl.tar.gz",
                    latest_version_clone2
                )))
            })
            .in_sequence(&mut seq);

        let mut install_dir_path_clone = install_dir.to_path_buf().clone();
        install_dir_path_clone.push("autonomi");
        mock_release_repo
            .expect_extract_release_archive()
            .with(
                eq(PathBuf::from(format!(
                    "/tmp/autonomi-{}-x86_64-unknown-linux-musl.tar.gz",
                    latest_version
                ))),
                always(), // We will extract to a temporary directory
            )
            .times(1)
            .returning(move |_, _| Ok(install_dir_path_clone.clone()))
            .in_sequence(&mut seq);

        let (version, bin_path) = install_bin(
            AssetType::Client,
            Box::new(mock_release_repo),
            PLATFORM,
            install_dir.path().to_path_buf(),
            None,
        )
        .await?;

        assert_eq!(version, Version::new(0, 86, 55));
        assert_eq!(bin_path, installed_autonomi.to_path_buf());

        Ok(())
    }

    #[tokio::test]
    async fn install_bin_should_install_a_specific_version() -> Result<()> {
        let specific_version = Version::new(0, 85, 0);
        let specific_version_clone = specific_version.clone();
        let temp_dir = assert_fs::TempDir::new()?;

        let install_dir = temp_dir.child("install");
        let installed_autonomi = install_dir.child("autonomi");
        // By creating this file we are 'pretending' that it was extracted to the specified
        // location. It's done so we can assert that the file is made executable.
        installed_autonomi.write_binary(b"fake autonomi bin")?;

        let mut mock_release_repo = MockSafeReleaseRepository::new();
        let mut seq = Sequence::new();
        mock_release_repo
            .expect_download_release_from_s3()
            .with(
                eq(&ReleaseType::Autonomi),
                eq(specific_version.clone()),
                always(), // Varies per platform
                eq(&ArchiveType::TarGz),
                always(), // Temporary directory which doesn't really matter
                always(), // Callback for progress bar which also doesn't matter
            )
            .times(1)
            .returning(move |_, _, _, _, _, _| {
                Ok(PathBuf::from(format!(
                    "/tmp/autonomi-{}-x86_64-unknown-linux-musl.tar.gz",
                    specific_version_clone
                )))
            })
            .in_sequence(&mut seq);

        let mut install_dir_path_clone = install_dir.to_path_buf().clone();
        install_dir_path_clone.push("autonomi");
        mock_release_repo
            .expect_extract_release_archive()
            .with(
                eq(PathBuf::from(format!(
                    "/tmp/autonomi-{}-x86_64-unknown-linux-musl.tar.gz",
                    specific_version.clone()
                ))),
                always(), // We will extract to a temporary directory
            )
            .times(1)
            .returning(move |_, _| Ok(install_dir_path_clone.clone()))
            .in_sequence(&mut seq);

        let (version, bin_path) = install_bin(
            AssetType::Client,
            Box::new(mock_release_repo),
            PLATFORM,
            install_dir.path().to_path_buf(),
            Some(specific_version.clone()),
        )
        .await?;

        assert_eq!(version, specific_version);
        assert_eq!(bin_path, installed_autonomi.to_path_buf());

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
        let safe_bin_file = tmp_data_path.child(AUTONOMI_BIN_NAME);
        safe_bin_file.write_binary(b"fake safe code")?;
        let safenode_bin_file = tmp_data_path.child("safenode");
        safenode_bin_file.write_binary(b"fake safenode code")?;
        let safenode_manager_bin_file = tmp_data_path.child("safenode-manager");
        safenode_manager_bin_file.write_binary(b"fake safenode-manager code")?;
        let testnet_bin_file = tmp_data_path.child("testnet");
        testnet_bin_file.write_binary(b"fake testnet code")?;

        let settings = Settings {
            autonomi_path: Some(safe_bin_file.to_path_buf()),
            autonomi_version: Some(Version::new(0, 75, 1)),
            safenode_path: Some(safenode_bin_file.to_path_buf()),
            safenode_version: Some(Version::new(0, 75, 2)),
            safenode_manager_path: Some(safenode_manager_bin_file.to_path_buf()),
            safenode_manager_version: Some(Version::new(0, 1, 8)),
        };

        settings.save(&settings_file.to_path_buf())?;

        settings_file.assert(predicates::path::is_file());
        let settings = Settings::read(&settings_file.to_path_buf())?;
        assert_eq!(settings.autonomi_path, Some(safe_bin_file.to_path_buf()));
        assert_eq!(settings.autonomi_version, Some(Version::new(0, 75, 1)));
        assert_eq!(
            settings.safenode_path,
            Some(safenode_bin_file.to_path_buf())
        );
        assert_eq!(settings.safenode_version, Some(Version::new(0, 75, 2)));
        assert_eq!(
            settings.safenode_manager_path,
            Some(safenode_manager_bin_file.to_path_buf())
        );
        assert_eq!(
            settings.safenode_manager_version,
            Some(Version::new(0, 1, 8))
        );
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
        let safe_bin_file = tmp_data_path.child(AUTONOMI_BIN_NAME);
        safe_bin_file.write_binary(b"fake safe code")?;
        let safenode_bin_file = tmp_data_path.child("safenode");
        safenode_bin_file.write_binary(b"fake safenode code")?;
        let safenode_manager_bin_file = tmp_data_path.child("safenode-manager");
        safenode_manager_bin_file.write_binary(b"fake safenode-manager code")?;
        let testnet_bin_file = tmp_data_path.child("testnet");
        testnet_bin_file.write_binary(b"fake testnet code")?;

        let settings = Settings {
            autonomi_path: Some(safe_bin_file.to_path_buf()),
            autonomi_version: Some(Version::new(0, 75, 1)),
            safenode_path: Some(safenode_bin_file.to_path_buf()),
            safenode_version: Some(Version::new(0, 75, 2)),
            safenode_manager_path: Some(safenode_manager_bin_file.to_path_buf()),
            safenode_manager_version: Some(Version::new(0, 1, 8)),
        };

        settings.save(&settings_file.to_path_buf())?;

        settings_file.assert(predicates::path::is_file());
        let settings = Settings::read(&settings_file.to_path_buf())?;
        assert_eq!(settings.autonomi_path, Some(safe_bin_file.to_path_buf()));
        assert_eq!(settings.autonomi_version, Some(Version::new(0, 75, 1)));
        assert_eq!(
            settings.safenode_path,
            Some(safenode_bin_file.to_path_buf())
        );
        assert_eq!(settings.safenode_version, Some(Version::new(0, 75, 2)));
        assert_eq!(
            settings.safenode_manager_path,
            Some(safenode_manager_bin_file.to_path_buf())
        );
        assert_eq!(
            settings.safenode_manager_version,
            Some(Version::new(0, 1, 8))
        );
        Ok(())
    }
}
