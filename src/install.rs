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
use indoc::indoc;
use std::env::consts::OS;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::BufWriter;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tar::Archive;

const SET_PATH_FILE_CONTENT: &str = indoc! {r#"
    #!/bin/sh
    case ":${PATH}:" in
        *:"$HOME/.safe/cli":*)
            ;;
        *)
            export PATH="$HOME/.safe/cli:$PATH"
            ;;
    esac
"#};

pub enum AssetType {
    Client,
    Node,
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
/// The version number of the installed binary.
pub async fn install_bin(
    asset_type: AssetType,
    release_repository: GithubReleaseRepository,
    asset_repository: S3AssetRepository,
    platform: &str,
    dest_dir_path: PathBuf,
    version: Option<String>,
) -> Result<String> {
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
    let mut entries = archive.entries()?;
    while let Some(entry_result) = entries.next() {
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

    let dest_dir_path = dest_dir_path
        .to_str()
        .ok_or_else(|| eyre!("Could not obtain path for shell profile"))?;
    println!("{bin_name} {version} is now available at {dest_dir_path}/safe");
    Ok(version)
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
        let mut shell_profile_file = OpenOptions::new()
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
    use super::{configure_shell_profile, install_bin, AssetType, SET_PATH_FILE_CONTENT};
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
    use std::path::Path;

    #[tokio::test]
    async fn install_bin_should_install_the_latest_version() -> Result<()> {
        let github_server = MockServer::start();
        let response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("latest_release_response_body.json"),
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
        let version = install_bin(
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
            std::path::Path::new("resources").join("latest_release_response_body.json"),
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
        let version = install_bin(
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
        let version = install_bin(
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

        Ok(())
    }

    #[tokio::test]
    async fn configure_shell_profile_should_put_client_on_path() -> Result<()> {
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
}
