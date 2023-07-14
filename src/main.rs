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

mod cmd;
mod github;
mod install;
mod s3;
mod update;

use clap::{Parser, Subcommand};
use cmd::{process_install_cmd, process_ls_command, process_update_cmd};
use color_eyre::Result;
use install::AssetType;
use std::path::PathBuf;

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
