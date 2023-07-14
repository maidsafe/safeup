// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

mod github;
mod install;
mod s3;
mod update;

use clap::{Parser, Subcommand};
use color_eyre::{eyre::eyre, Result};
use github::GithubReleaseRepository;
use install::{AssetType, Settings};
use lazy_static::lazy_static;
use prettytable::{Cell, Row, Table};
use s3::S3AssetRepository;
use std::collections::HashMap;
use std::env::consts::{ARCH, OS};
use std::path::PathBuf;
use update::{perform_update_assessment, UpdateAssessmentResult};

const GITHUB_API_URL: &str = "https://api.github.com";
const ORG_NAME: &str = "maidsafe";
const REPO_NAME: &str = "safe_network";
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
            AssetType::Testnet,
            "https://sn-testnet.s3.eu-west-2.amazonaws.com",
        );
        m
    };
}

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the safe client binary.
    ///
    /// The location is platform specific:
    /// - Linux/macOS: $HOME/.local/bin
    /// - Windows: C:\Users\<username>\safe
    ///
    /// On Linux/macOS, the Bash shell profile will be modified to add $HOME/.local/bin to the PATH
    /// variable. On Windows, the user Path variable will be modified to add C:\Users\<username>\safe.
    #[clap(verbatim_doc_comment)]
    Client {
        /// Override the default installation path.
        ///
        /// Any directories that don't exist will be created.
        #[arg(short = 'p', long, value_name = "DIRECTORY")]
        path: Option<PathBuf>,

        /// Disable modification of the shell profile.
        #[arg(short = 'n', long)]
        no_modify_shell_profile: bool,

        /// Install a specific version rather than the latest.
        #[arg(short = 'v', long)]
        version: Option<String>,
    },
    /// Install the safenode binary.
    ///
    /// The location is platform specific:
    /// - Linux/macOS: $HOME/.local/bin
    /// - Windows: C:\Users\<username>\safe
    ///
    /// On Linux/macOS, the Bash shell profile will be modified to add $HOME/.local/bin to the PATH
    /// variable. On Windows, the user Path variable will be modified to add C:\Users\<username>\safe.
    #[clap(verbatim_doc_comment)]
    Node {
        /// Override the default installation path.
        ///
        /// Any directories that don't exist will be created.
        #[arg(short = 'p', long, value_name = "DIRECTORY")]
        path: Option<PathBuf>,

        /// Disable modification of the shell profile.
        #[arg(short = 'n', long)]
        no_modify_shell_profile: bool,

        /// Install a specific version rather than the latest.
        #[arg(short = 'v', long)]
        version: Option<String>,
    },
    /// Install the testnet binary.
    ///
    /// The location is platform specific:
    /// - Linux/macOS: $HOME/.local/bin
    /// - Windows: C:\Users\<username>\safe
    ///
    /// On Linux/macOS, the Bash shell profile will be modified to add $HOME/.local/bin to the PATH
    /// variable. On Windows, the user Path variable will be modified to add C:\Users\<username>\safe.
    #[clap(verbatim_doc_comment)]
    Testnet {
        /// Override the default installation path.
        ///
        /// Any directories that don't exist will be created.
        #[arg(short = 'p', long, value_name = "DIRECTORY")]
        path: Option<PathBuf>,

        /// Disable modification of the shell profile.
        #[arg(short = 'n', long)]
        no_modify_shell_profile: bool,

        /// Install a specific version rather than the latest.
        #[arg(short = 'v', long)]
        version: Option<String>,
    },
    /// Update installed components.
    #[clap(verbatim_doc_comment)]
    Update {},
    /// List installed components.
    #[clap(name = "ls", verbatim_doc_comment)]
    List {},
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Client {
            path,
            no_modify_shell_profile,
            version,
        }) => {
            println!("**************************************");
            println!("*                                    *");
            println!("*          Installing safe           *");
            println!("*                                    *");
            println!("**************************************");
            install::check_prerequisites()?;
            process_install_cmd(AssetType::Client, path, version, no_modify_shell_profile).await
        }
        Some(Commands::Node {
            path,
            no_modify_shell_profile,
            version,
        }) => {
            println!("**************************************");
            println!("*                                    *");
            println!("*          Installing safenode       *");
            println!("*                                    *");
            println!("**************************************");
            install::check_prerequisites()?;
            process_install_cmd(AssetType::Node, path, version, no_modify_shell_profile).await
        }
        Some(Commands::Testnet {
            path,
            no_modify_shell_profile,
            version,
        }) => {
            println!("**************************************");
            println!("*                                    *");
            println!("*          Installing testnet        *");
            println!("*                                    *");
            println!("**************************************");
            install::check_prerequisites()?;
            process_install_cmd(AssetType::Testnet, path, version, no_modify_shell_profile).await
        }
        Some(Commands::Update {}) => {
            println!("**************************************");
            println!("*                                    *");
            println!("*          Updating components       *");
            println!("*                                    *");
            println!("**************************************");
            process_update_cmd().await
        }
        Some(Commands::List {}) => process_ls_command(),
        None => Ok(()),
    }
}

async fn process_install_cmd(
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

    do_install_binary(&asset_type, dest_dir_path.clone(), version).await?;

    if !no_modify_shell_profile {
        install::configure_shell_profile(
            &dest_dir_path.clone(),
            &get_shell_profile_path()?,
            &safe_config_dir_path.join("env"),
        )
        .await?
    }

    Ok(())
}

async fn process_update_cmd() -> Result<()> {
    let platform = get_platform()?;
    let safe_config_dir_path = get_safe_config_dir_path()?;
    let settings_file_path = safe_config_dir_path.join("safeup.json");
    let settings = Settings::read(&settings_file_path)?;
    let release_repository = GithubReleaseRepository::new(GITHUB_API_URL, ORG_NAME, REPO_NAME);
    for asset_type in AssetType::variants() {
        println!("Retrieving latest version for {asset_type}...");
        let (_, latest_version) = release_repository
            .get_latest_asset_name(&asset_type, &platform)
            .await?;
        println!("Latest version of {asset_type} is {latest_version}");
        if settings.is_installed(&asset_type) {
            println!(
                "Current version of {asset_type} is {}",
                settings.get_installed_version(&asset_type)
            );
        }
        let decision = perform_update_assessment(&asset_type, &latest_version, &settings)?;
        match decision {
            UpdateAssessmentResult::PerformUpdate => {
                println!("Updating {asset_type} to {latest_version}...");
                let installed_path = settings.get_install_path(&asset_type).clone();
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

fn process_ls_command() -> Result<()> {
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
        let installed_path = settings.get_install_path(&asset_type);
        let wrapped_install_path = textwrap::wrap(
            &installed_path
                .to_str()
                .ok_or_else(|| eyre!("could not obtain install path"))?,
            WRAP_LENGTH,
        )
        .join("\n");
        table.add_row(Row::new(vec![
            Cell::new(&asset_type.to_string()),
            Cell::new(&settings.get_installed_version(&asset_type)),
            Cell::new(&wrapped_install_path),
        ]));
    }
    table.printstd();
    Ok(())
}

async fn do_install_binary(
    asset_type: &AssetType,
    dest_dir_path: PathBuf,
    version: Option<String>,
) -> Result<()> {
    let platform = get_platform()?;
    let asset_repository = S3AssetRepository::new(ASSET_TYPE_BUCKET_MAP[asset_type]);
    let release_repository = GithubReleaseRepository::new(GITHUB_API_URL, ORG_NAME, REPO_NAME);
    let (installed_version, bin_path) = install::install_bin(
        asset_type.clone(),
        release_repository,
        asset_repository,
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
            settings.safe_path = bin_path;
            settings.safe_version = installed_version;
        }
        AssetType::Node => {
            settings.safenode_path = bin_path;
            settings.safenode_version = installed_version;
        }
        AssetType::Testnet => {
            settings.testnet_path = bin_path;
            settings.testnet_version = installed_version;
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
        Ok(shell) => match shell.as_str() {
            "/bin/bash" => ".bashrc",
            "/bin/zsh" => ".zshrc",
            _ => return Err(eyre!("shell {shell} is not supported by safeup")),
        },
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
