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
use install::AssetType;
use s3::S3AssetRepository;
use std::env::consts::{ARCH, OS};
use std::path::PathBuf;

const GITHUB_API_URL: &str = "https://api.github.com";
const ORG_NAME: &str = "maidsafe";
const REPO_NAME: &str = "safe_network";
const SAFE_BUCKET_NAME: &str = "https://sn-cli.s3.eu-west-2.amazonaws.com";

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
    /// The default install path is /usr/local/bin if you run safeup as root, or ~/.safe/cli if you
    /// run as the current user.
    Client {
        /// Override the default installation path.
        ///
        /// Any directories that don't exist will be created.
        #[arg(short, long, value_name = "DIRECTORY")]
        path: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let platform = get_platform()?;
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Commands::Client { path }) => {
            let dest_dir_path = if let Some(path) = path {
                path
            } else {
                if is_running_elevated() {
                    std::path::PathBuf::from("/usr/local/bin")
                } else {
                    let home_dir_path = dirs_next::home_dir()
                        .ok_or_else(|| eyre!("Could not retrieve user's home directory"))?;
                    home_dir_path.join(".safe").join("cli")
                }
            };
            let release_repository =
                GithubReleaseRepository::new(GITHUB_API_URL, ORG_NAME, REPO_NAME);
            let asset_repository = S3AssetRepository::new(SAFE_BUCKET_NAME);
            install::install_bin(
                AssetType::Client,
                release_repository,
                asset_repository,
                &platform,
                dest_dir_path.clone(),
            )
            .await?;
            Ok(())
        }
        None => {
            println!("interactive gui");
            Ok(())
        }
    };
    result
}

fn get_platform() -> Result<String> {
    match OS {
        "linux" => match ARCH {
            "x86_64" => return Ok(format!("{}-unknown-{}-musl", ARCH, OS)),
            "armv7" => return Ok(format!("{}-unknown-{}-musleabihf", ARCH, OS)),
            "arm" => return Ok(format!("{}-unknown-{}-musleabi", ARCH, OS)),
            "aarch64" => return Ok(format!("{}-unknown-{}-musl", ARCH, OS)),
            &_ => {
                return Err(eyre!(
                    "We currently do not have binaries for the {OS}/{ARCH} combination"
                ))
            }
        },
        "windows" => {
            if ARCH != "x86_64" {
                return Err(eyre!(
                    "We currently only have x86_64 binaries available for Windows"
                ));
            }
            return Ok(format!("{}-pc-{}-msvc", ARCH, OS));
        }
        "macos" => {
            if ARCH != "x86_64" {
                return Err(eyre!(
                    "We currently only have x86_64 binaries available for macOS"
                ));
            }
            return Ok(format!("{}-apple-darwin", ARCH));
        }
        &_ => {
            return Err(eyre!("{OS} is not currently supported by safeup"));
        }
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
