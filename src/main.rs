// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod github;
mod install;
mod s3;

use clap::{Parser, Subcommand};
use color_eyre::{eyre::eyre, Result};
use github::GithubReleaseRepository;
use install::{AssetType, Settings};
use s3::S3AssetRepository;
use std::env::consts::{ARCH, OS};
use std::path::PathBuf;

const GITHUB_API_URL: &str = "https://api.github.com";
const ORG_NAME: &str = "maidsafe";
const REPO_NAME: &str = "safe_network";
const SAFE_BUCKET_NAME: &str = "https://sn-cli.s3.eu-west-2.amazonaws.com";
const SAFENODE_BUCKET_NAME: &str = "https://sn-node.s3.eu-west-2.amazonaws.com";
const TESTNET_BUCKET_NAME: &str = "https://sn-testnet.s3.eu-west-2.amazonaws.com";

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the latest version of safe.
    ///
    /// If running without elevated privileges, safe will be installed to $HOME/.local/bin, and
    /// the shell profile will be modified to put this location on PATH.
    ///
    /// Otherwise safe will be installed to /usr/local/bin.
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
    /// Install the latest version of safenode.
    ///
    /// If running without elevated privileges, safenode will be installed to $HOME/.local/bin, and
    /// your shell profile will be modified to put this location on PATH.
    ///
    /// Otherwise safenode will be installed to /usr/local/bin.
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
    /// Install the latest version of testnet.
    ///
    /// If running without elevated privileges, testnet will be installed to $HOME/.local/bin, and
    /// your shell profile will be modified to put this location on PATH.
    ///
    /// Otherwise testnet will be installed to /usr/local/bin.
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
            install(
                AssetType::Client,
                SAFE_BUCKET_NAME,
                path,
                version,
                no_modify_shell_profile,
            )
            .await
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
            install(
                AssetType::Node,
                SAFENODE_BUCKET_NAME,
                path,
                version,
                no_modify_shell_profile,
            )
            .await
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
            install(
                AssetType::Testnet,
                TESTNET_BUCKET_NAME,
                path,
                version,
                no_modify_shell_profile,
            )
            .await
        }
        None => Ok(()),
    }
}

async fn install(
    asset_type: AssetType,
    bucket_name: &str,
    path: Option<PathBuf>,
    version: Option<String>,
    no_modify_shell_profile: bool,
) -> Result<()> {
    let platform = get_platform()?;
    let running_elevated = is_running_elevated();
    let safe_config_dir_path = get_safe_config_dir_path()?;

    let dest_dir_path = if let Some(path) = path {
        path
    } else if running_elevated {
        std::path::PathBuf::from("/usr/local/bin")
    } else {
        get_install_dest_dir_path()?
    };

    let release_repository = GithubReleaseRepository::new(GITHUB_API_URL, ORG_NAME, REPO_NAME);
    let asset_repository = S3AssetRepository::new(bucket_name);
    let (_, bin_path) = install::install_bin(
        asset_type.clone(),
        release_repository,
        asset_repository,
        &platform,
        dest_dir_path.clone(),
        version,
    )
    .await?;

    if !running_elevated && !no_modify_shell_profile {
        install::configure_shell_profile(
            &dest_dir_path.clone(),
            &get_shell_profile_path()?,
            &safe_config_dir_path.join("env"),
        )
        .await?
    }

    let settings_file_path = safe_config_dir_path.join("safeup.json");
    let mut settings = Settings::read(&settings_file_path)?;
    match asset_type {
        AssetType::Client => settings.safe_path = bin_path,
        AssetType::Node => settings.safenode_path = bin_path,
        AssetType::Testnet => settings.testnet_path = bin_path,
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
                return Err(eyre!(
                    "We currently only have x86_64 binaries available for macOS"
                ));
            }
            Ok(format!("{}-apple-darwin", ARCH))
        }
        &_ => Err(eyre!("{OS} is not currently supported by safeup")),
    }
}

#[cfg(target_os = "linux")]
fn is_running_elevated() -> bool {
    users::get_effective_uid() == 0
}

#[cfg(target_os = "macos")]
fn is_running_elevated() -> bool {
    let uid = users::get_effective_uid();
    let sudo_uid = users::get_current_uid();
    uid == sudo_uid
}

#[cfg(target_os = "windows")]
fn is_running_elevated() -> bool {
    false
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

#[cfg(target_os = "macos")]
fn get_shell_profile_path() -> Result<PathBuf> {
    let home_dir_path =
        dirs_next::home_dir().ok_or_else(|| eyre!("Could not retrieve user's home directory"))?;
    Ok(home_dir_path.join(".zshrc"))
}

fn get_safe_config_dir_path() -> Result<PathBuf> {
    let config_dir_path = dirs_next::config_dir()
        .ok_or_else(|| eyre!("Could not retrieve user's config directory"))?;
    let safe_config_dir_path = config_dir_path.join("safe");
    std::fs::create_dir_all(safe_config_dir_path.clone())?;
    Ok(safe_config_dir_path)
}

#[cfg(target_os = "windows")]
fn get_install_dest_dir_path() -> Result<PathBuf> {
    let home_dir_path =
        dirs_next::home_dir().ok_or_else(|| eyre!("Could not retrieve user's home directory"))?;
    let safe_dir_path = home_dir_path.join("safe");
    std::fs::create_dir_all(safe_dir_path.clone())?;
    Ok(safe_dir_path)
}

#[cfg(target_family = "unix")]
fn get_install_dest_dir_path() -> Result<PathBuf> {
    let home_dir_path =
        dirs_next::home_dir().ok_or_else(|| eyre!("Could not retrieve user's home directory"))?;
    let safe_dir_path = home_dir_path.join(".local").join("bin");
    std::fs::create_dir_all(safe_dir_path.clone())?;
    Ok(safe_dir_path)
}
