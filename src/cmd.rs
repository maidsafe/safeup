// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::install::{AssetType, Settings};
use crate::update::{perform_update_assessment, UpdateAssessmentResult};
use color_eyre::{eyre::eyre, Result};
use lazy_static::lazy_static;
use prettytable::{Cell, Row, Table};
use semver::Version;
use sn_releases::SafeReleaseRepoActions;
use std::collections::HashMap;
use std::env::consts::{ARCH, OS};
use std::path::PathBuf;

const WRAP_LENGTH: usize = 80;

lazy_static! {
    static ref ASSET_TYPE_BUCKET_MAP: HashMap<AssetType, &'static str> = {
        let mut m = HashMap::new();
        m.insert(
            AssetType::Client,
            "https://sn-cli.s3.eu-west-2.amazonaws.com",
        );
        m.insert(
            AssetType::Node,
            "https://sn-node.s3.eu-west-2.amazonaws.com",
        );
        m.insert(
            AssetType::NodeManager,
            "https://sn-node-manager.s3.eu-west-2.amazonaws.com",
        );
        m
    };
}

pub(crate) async fn process_install_cmd(
    asset_type: AssetType,
    custom_path: Option<PathBuf>,
    version: Option<String>,
    no_modify_shell_profile: bool,
) -> Result<()> {
    let safe_config_dir_path = get_safe_config_dir_path()?;
    let dest_dir_path = if let Some(path) = custom_path {
        path
    } else {
        get_default_install_path()?
    };

    let version = if let Some(version) = version {
        Some(Version::parse(&version)?)
    } else {
        None
    };
    do_install_binary(&asset_type, dest_dir_path.clone(), version).await?;

    if !no_modify_shell_profile {
        crate::install::configure_shell_profile(
            &dest_dir_path.clone(),
            &get_shell_profile_path()?,
            &safe_config_dir_path.join("env"),
        )
        .await?
    }

    Ok(())
}

pub(crate) async fn process_update_cmd() -> Result<()> {
    let safe_config_dir_path = get_safe_config_dir_path()?;
    let settings_file_path = safe_config_dir_path.join("safeup.json");
    let settings = Settings::read(&settings_file_path)?;
    let release_repo = <dyn SafeReleaseRepoActions>::default_config();

    for asset_type in AssetType::variants() {
        println!("Retrieving latest version for {asset_type}...");
        let latest_version = release_repo
            .get_latest_version(&asset_type.get_release_type())
            .await?;
        println!("Latest version of {asset_type} is {latest_version}");

        let decision = perform_update_assessment(&asset_type, &latest_version, &settings)?;
        match decision {
            UpdateAssessmentResult::PerformUpdate(installed_path) => {
                println!("Updating {asset_type} to {latest_version}...");
                let installed_dir_path = installed_path
                    .parent()
                    .ok_or_else(|| eyre!("could not retrieve parent directory"))?;
                do_install_binary(
                    &asset_type,
                    installed_dir_path.to_path_buf(),
                    Some(latest_version),
                )
                .await?;
            }
            UpdateAssessmentResult::AtLatestVersion => {
                println!(
                    "{asset_type} is already at {latest_version}, \
                    which is the latest version."
                );
                println!("No update will be performed.")
            }
            UpdateAssessmentResult::NoPreviousInstallation => {
                println!("There is no previous installation for the {asset_type} component.");
                println!("No update will be performed.")
            }
        }
        println!();
    }
    Ok(())
}

pub(crate) fn process_ls_command() -> Result<()> {
    let safe_config_dir_path = get_safe_config_dir_path()?;
    let settings_file_path = safe_config_dir_path.join("safeup.json");
    let settings = Settings::read(&settings_file_path)?;
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Name"),
        Cell::new("Version"),
        Cell::new("Path"),
    ]));
    for asset_type in AssetType::variants() {
        if let Some((installed_path, installed_version)) = settings.get_install_details(&asset_type)
        {
            let wrapped_install_path = textwrap::wrap(
                installed_path
                    .to_str()
                    .ok_or_else(|| eyre!("could not obtain install path"))?,
                WRAP_LENGTH,
            )
            .join("\n");
            table.add_row(Row::new(vec![
                Cell::new(&asset_type.to_string()),
                Cell::new(&installed_version.to_string()),
                Cell::new(&wrapped_install_path),
            ]));
        }
    }
    table.printstd();
    Ok(())
}

async fn do_install_binary(
    asset_type: &AssetType,
    dest_dir_path: PathBuf,
    version: Option<Version>,
) -> Result<()> {
    let platform = get_platform()?;
    let release_repo = <dyn SafeReleaseRepoActions>::default_config();
    let (installed_version, bin_path) = crate::install::install_bin(
        asset_type.clone(),
        release_repo,
        &platform,
        dest_dir_path.clone(),
        version,
    )
    .await?;

    let safe_config_dir_path = get_safe_config_dir_path()?;
    let settings_file_path = safe_config_dir_path.join("safeup.json");
    let mut settings = Settings::read(&settings_file_path)?;
    match asset_type {
        AssetType::Client => {
            settings.safe_path = Some(bin_path);
            settings.safe_version = Some(installed_version);
        }
        AssetType::Node => {
            settings.safenode_path = Some(bin_path);
            settings.safenode_version = Some(installed_version);
        }
        AssetType::NodeManager => {
            settings.safenode_manager_path = Some(bin_path);
            settings.safenode_manager_version = Some(installed_version);
        }
    }
    settings.save(&settings_file_path)?;

    Ok(())
}

fn get_platform() -> Result<String> {
    match OS {
        "linux" => match ARCH {
            "x86_64" => Ok(format!("{}-unknown-{}-musl", ARCH, OS)),
            "armv7" => Ok(format!("{}-unknown-{}-musleabihf", ARCH, OS)),
            "arm" => Ok(format!("{}-unknown-{}-musleabi", ARCH, OS)),
            "aarch64" => Ok(format!("{}-unknown-{}-musl", ARCH, OS)),
            &_ => Err(eyre!(
                "We currently do not have binaries for the {OS}/{ARCH} combination"
            )),
        },
        "windows" => {
            if ARCH != "x86_64" {
                return Err(eyre!(
                    "We currently only have x86_64 binaries available for Windows"
                ));
            }
            Ok(format!("{}-pc-{}-msvc", ARCH, OS))
        }
        "macos" => {
            if ARCH != "x86_64" {
                println!(
                    "We currently only have x86_64 binaries available for macOS. On Mx Macs, Rosetta will run these x86_64 binaries."
                );
            }
            Ok(format!("{}-apple-darwin", ARCH))
        }
        &_ => Err(eyre!("{OS} is not currently supported by safeup")),
    }
}

#[cfg(target_os = "linux")]
fn get_shell_profile_path() -> Result<PathBuf> {
    let home_dir_path =
        dirs_next::home_dir().ok_or_else(|| eyre!("Could not retrieve user's home directory"))?;
    Ok(home_dir_path.join(".bashrc"))
}

/// We won't actually end up doing anything on Windows with the shell profile, so we can just
/// return back the home directory.
#[cfg(target_os = "windows")]
fn get_shell_profile_path() -> Result<PathBuf> {
    let home_dir_path =
        dirs_next::home_dir().ok_or_else(|| eyre!("Could not retrieve user's home directory"))?;
    Ok(home_dir_path.to_path_buf())
}

/// On macOS, it's not necessarily the case that ZSH will be the default shell.
/// On GHA they are running Bash.
#[cfg(target_os = "macos")]
fn get_shell_profile_path() -> Result<PathBuf> {
    let profile_file_name = match std::env::var("SHELL") {
        Ok(shell) => {
            let pb = PathBuf::from(shell.clone());
            let shell_bin_name = pb
                .file_stem()
                .ok_or_else(|| eyre!(format!("Unable to obtain file stem from {shell}")))?
                .to_string_lossy()
                .to_string();
            match shell_bin_name.as_str() {
                "bash" => ".bashrc",
                "zsh" => ".zshrc",
                _ => return Err(eyre!("shell {shell} is not supported by safeup")),
            }
        }
        Err(e) => return Err(eyre!(e)),
    };
    let home_dir_path =
        dirs_next::home_dir().ok_or_else(|| eyre!("Could not retrieve user's home directory"))?;
    Ok(home_dir_path.join(profile_file_name))
}

fn get_safe_config_dir_path() -> Result<PathBuf> {
    let config_dir_path = dirs_next::config_dir()
        .ok_or_else(|| eyre!("Could not retrieve user's config directory"))?;
    let safe_config_dir_path = config_dir_path.join("safe");
    std::fs::create_dir_all(safe_config_dir_path.clone())?;
    Ok(safe_config_dir_path)
}

#[cfg(target_os = "windows")]
fn get_default_install_path() -> Result<PathBuf> {
    let home_dir_path =
        dirs_next::home_dir().ok_or_else(|| eyre!("Could not retrieve user's home directory"))?;
    let safe_dir_path = home_dir_path.join("safe");
    std::fs::create_dir_all(safe_dir_path.clone())?;
    Ok(safe_dir_path)
}

#[cfg(target_family = "unix")]
fn get_default_install_path() -> Result<PathBuf> {
    let home_dir_path =
        dirs_next::home_dir().ok_or_else(|| eyre!("Could not retrieve user's home directory"))?;
    let safe_dir_path = home_dir_path.join(".local").join("bin");
    std::fs::create_dir_all(safe_dir_path.clone())?;
    Ok(safe_dir_path)
}
