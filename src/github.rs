// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::install::AssetType;
use chrono::{DateTime, Utc};
use color_eyre::{eyre::eyre, Result};
use lazy_static::lazy_static;
use reqwest::{header::HeaderMap, Client, Response};
use serde_json::Value;
use std::collections::HashMap;

lazy_static! {
    static ref ASSET_TYPE_CRATE_NAME_MAP: HashMap<AssetType, &'static str> = {
        let mut m = HashMap::new();
        m.insert(AssetType::Client, "sn_cli");
        m.insert(AssetType::Node, "sn_node");
        m.insert(AssetType::Testnet, "sn_testnet");
        m
    };
}

pub struct GithubReleaseRepository {
    pub base_url: String,
    pub organisation_name: String,
    pub repository_name: String,
}

impl GithubReleaseRepository {
    pub fn new(base_url: &str, organisation_name: &str, repository_name: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            organisation_name: organisation_name.to_string(),
            repository_name: repository_name.to_string(),
        }
    }

    /// Retrieves the asset name of the latest release for the specified type and platform.
    ///
    /// # Arguments
    ///
    /// * `asset_type` - Either the client or node.
    /// * `platform` - The target triple platform of the binary to be installed.
    ///
    /// # Returns
    ///
    /// A tuple containing the name of the asset and the version number for the latest release.
    ///
    /// # Errors
    ///
    /// Returns an `eyre::Report` if an error occurs during the retrieval process. Possible error
    /// conditions include network errors, JSON parsing errors, and missing or invalid data in the
    /// response body.
    pub async fn get_latest_asset_name(
        &self,
        asset_type: &AssetType,
        platform: &str,
    ) -> Result<(String, String)> {
        let mut page = 1;
        let per_page = 100;
        let mut latest_release: Option<(String, DateTime<Utc>)> = None;
        let target_tag_name = *ASSET_TYPE_CRATE_NAME_MAP
            .get(&asset_type)
            .ok_or_else(|| eyre!("Could not obtain asset name"))?;

        loop {
            let response = self.get_releases_page(page, per_page).await?;
            let headers = response.headers().clone();
            let releases = response.json::<Value>().await?;
            if let Value::Array(releases) = releases {
                for release in releases {
                    if let Value::Object(release) = release {
                        if let (Some(Value::String(tag_name)), Some(Value::String(created_at))) =
                            (release.get("tag_name"), release.get("created_at"))
                        {
                            if tag_name.starts_with(target_tag_name) {
                                let created_at = created_at.parse::<DateTime<Utc>>()?;
                                match latest_release {
                                    Some((_, date)) if created_at > date => {
                                        latest_release = Some((tag_name.clone(), created_at));
                                    }
                                    None => {
                                        latest_release = Some((tag_name.clone(), created_at));
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            if self.has_next_page(&headers).await? {
                page += 1;
            } else {
                break;
            }
        }

        let tag_name = latest_release
            .ok_or_else(|| eyre!("No release found for {asset_type}"))?
            .0;
        let version = self.get_version_from_tag_name(&tag_name)?;
        let release = self.get_release(&tag_name).await?;
        let asset_name = self.get_versioned_asset_name(&asset_type, platform, &version);
        if self.release_has_asset(&release, &asset_name)? {
            return Ok((asset_name, version));
        }

        Err(eyre!(
            "Release {tag_name} has no asset for platform {platform}"
        ))
    }

    pub fn get_versioned_asset_name(
        &self,
        asset_type: &AssetType,
        platform: &str,
        version: &str,
    ) -> String {
        match asset_type {
            AssetType::Client => format!("safe-{version}-{platform}.tar.gz"),
            AssetType::Node => format!("safenode-{version}-{platform}.tar.gz"),
            AssetType::Testnet => format!("testnet-{version}-{platform}.tar.gz"),
        }
    }

    async fn get_releases_page(&self, page: u32, per_page: u32) -> Result<Response> {
        let client = Client::new();
        let response = client
            .get(format!(
                "{}/repos/{}/{}/releases?page={}&per_page={}",
                self.base_url, self.organisation_name, self.repository_name, page, per_page
            ))
            .header("User-Agent", "request")
            .send()
            .await?;
        Ok(response)
    }

    async fn has_next_page(&self, headers: &HeaderMap) -> Result<bool> {
        if let Some(links) = headers.get("link") {
            let links = links.to_str()?;
            Ok(links.split(',').any(|link| link.contains("rel=\"next\"")))
        } else {
            Ok(false)
        }
    }

    async fn get_release(&self, tag_name: &str) -> Result<Value> {
        let client = Client::new();
        let response = client
            .get(format!(
                "{}/repos/{}/{}/releases/tags/{}",
                self.base_url, self.organisation_name, self.repository_name, tag_name
            ))
            .header("User-Agent", "request")
            .send()
            .await?
            .json::<Value>()
            .await?;
        Ok(response)
    }

    fn release_has_asset(&self, release: &Value, asset_name: &str) -> Result<bool> {
        let assets = release["assets"]
            .as_array()
            .ok_or_else(|| eyre!("Response body does not contain 'assets' value"))?;
        let release_has_asset = assets.iter().any(|a| {
            if let Some(name) = a["name"].as_str() {
                name == asset_name
            } else {
                false
            }
        });
        Ok(release_has_asset)
    }

    fn get_version_from_tag_name(&self, tag_name: &str) -> Result<String> {
        let mut parts = tag_name.split('-');
        parts.next();
        let version = parts
            .next()
            .ok_or_else(|| eyre!("Could not parse version from tag: {tag_name}"))?
            .to_string();
        Ok(version.trim_start_matches('v').to_string())
    }
}

#[cfg(test)]
mod test {
    use super::{AssetType, GithubReleaseRepository};
    use color_eyre::{eyre::eyre, Result};
    use httpmock::prelude::*;

    #[tokio::test]
    async fn get_latest_asset_name_for_client_should_get_asset_name_with_the_latest_version(
    ) -> Result<()> {
        let server = MockServer::start();
        let releases_response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("releases_response_body.json"),
        )?;
        let releases_list_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases");
            then.status(200)
                .header("server", "Github.com")
                .body(releases_response_body);
        });

        let sn_cli_response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("sn_cli_release_response_body.json"),
        )?;
        let release_by_tag_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/tags/sn_cli-v0.77.13");
            then.status(200)
                .header("server", "Github.com")
                .body(sn_cli_response_body);
        });

        let repository =
            GithubReleaseRepository::new(&server.base_url(), "maidsafe", "safe_network");
        let (asset_name, version) = repository
            .get_latest_asset_name(&AssetType::Client, "x86_64-unknown-linux-musl")
            .await?;

        releases_list_mock.assert();
        release_by_tag_mock.assert();
        assert_eq!(asset_name, "safe-0.77.13-x86_64-unknown-linux-musl.tar.gz");
        assert_eq!(version, "0.77.13");
        Ok(())
    }

    #[tokio::test]
    async fn get_latest_asset_name_for_client_should_return_error_when_release_has_no_asset(
    ) -> Result<()> {
        let server = MockServer::start();
        let releases_response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("releases_response_body.json"),
        )?;
        let releases_list_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases");
            then.status(200)
                .header("server", "Github.com")
                .body(releases_response_body);
        });
        let sn_cli_response_body = std::fs::read_to_string(
            std::path::Path::new("resources")
                .join("sn_cli_release_missing_asset_response_body.json"),
        )?;
        let release_by_tag_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/tags/sn_cli-v0.77.13");
            then.status(200)
                .header("server", "Github.com")
                .body(sn_cli_response_body);
        });

        let repository =
            GithubReleaseRepository::new(&server.base_url(), "maidsafe", "safe_network");
        let result = repository
            .get_latest_asset_name(&AssetType::Client, "x86_64-unknown-linux-musl")
            .await;

        releases_list_mock.assert();
        release_by_tag_mock.assert();
        match result {
            Err(msg) => {
                assert_eq!(
                    msg.to_string(),
                    "Release sn_cli-v0.77.13 has no asset for platform x86_64-unknown-linux-musl"
                );
                Ok(())
            }
            Ok(_) => Err(eyre!("This test case is expected to return an error")),
        }
    }

    #[tokio::test]
    async fn get_latest_asset_name_for_node_should_get_asset_name_with_the_latest_version(
    ) -> Result<()> {
        let server = MockServer::start();
        let releases_response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("releases_response_body.json"),
        )?;
        let releases_list_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases");
            then.status(200)
                .header("server", "Github.com")
                .body(releases_response_body);
        });

        let sn_cli_response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("sn_node_release_response_body.json"),
        )?;
        let release_by_tag_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/tags/sn_node-v0.83.11");
            then.status(200)
                .header("server", "Github.com")
                .body(sn_cli_response_body);
        });

        let repository =
            GithubReleaseRepository::new(&server.base_url(), "maidsafe", "safe_network");
        let (asset_name, version) = repository
            .get_latest_asset_name(&AssetType::Node, "x86_64-unknown-linux-musl")
            .await?;

        releases_list_mock.assert();
        release_by_tag_mock.assert();
        assert_eq!(
            asset_name,
            "safenode-0.83.11-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(version, "0.83.11");
        Ok(())
    }

    #[tokio::test]
    async fn get_latest_asset_name_for_node_should_return_error_when_release_has_no_asset(
    ) -> Result<()> {
        let server = MockServer::start();
        let releases_response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("releases_response_body.json"),
        )?;
        let releases_list_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases");
            then.status(200)
                .header("server", "Github.com")
                .body(releases_response_body);
        });
        let sn_cli_response_body = std::fs::read_to_string(
            std::path::Path::new("resources")
                .join("sn_node_release_missing_asset_response_body.json"),
        )?;
        let release_by_tag_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/tags/sn_node-v0.83.11");
            then.status(200)
                .header("server", "Github.com")
                .body(sn_cli_response_body);
        });

        let repository =
            GithubReleaseRepository::new(&server.base_url(), "maidsafe", "safe_network");
        let result = repository
            .get_latest_asset_name(&AssetType::Node, "x86_64-unknown-linux-musl")
            .await;

        releases_list_mock.assert();
        release_by_tag_mock.assert();
        match result {
            Err(msg) => {
                assert_eq!(
                    msg.to_string(),
                    "Release sn_node-v0.83.11 has no asset for platform x86_64-unknown-linux-musl"
                );
                Ok(())
            }
            Ok(_) => Err(eyre!("This test case is expected to return an error")),
        }
    }

    #[tokio::test]
    async fn get_latest_asset_name_for_testnet_should_get_asset_name_with_the_latest_version(
    ) -> Result<()> {
        let server = MockServer::start();
        let releases_response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("releases_response_body.json"),
        )?;
        let releases_list_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases");
            then.status(200)
                .header("server", "Github.com")
                .body(releases_response_body);
        });

        let sn_testnet_response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("sn_testnet_release_response_body.json"),
        )?;
        let release_by_tag_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/tags/sn_testnet-v0.1.15");
            then.status(200)
                .header("server", "Github.com")
                .body(sn_testnet_response_body);
        });

        let repository =
            GithubReleaseRepository::new(&server.base_url(), "maidsafe", "safe_network");
        let (asset_name, version) = repository
            .get_latest_asset_name(&AssetType::Testnet, "x86_64-unknown-linux-musl")
            .await?;

        releases_list_mock.assert();
        release_by_tag_mock.assert();
        assert_eq!(
            asset_name,
            "testnet-0.1.15-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(version, "0.1.15");
        Ok(())
    }

    #[tokio::test]
    async fn get_latest_asset_name_for_testnet_should_return_error_when_release_has_no_asset(
    ) -> Result<()> {
        let server = MockServer::start();
        let releases_response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("releases_response_body.json"),
        )?;
        let releases_list_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases");
            then.status(200)
                .header("server", "Github.com")
                .body(releases_response_body);
        });
        let sn_testnet_response_body = std::fs::read_to_string(
            std::path::Path::new("resources")
                .join("sn_testnet_release_missing_asset_response_body.json"),
        )?;
        let release_by_tag_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/tags/sn_testnet-v0.1.15");
            then.status(200)
                .header("server", "Github.com")
                .body(sn_testnet_response_body);
        });

        let repository =
            GithubReleaseRepository::new(&server.base_url(), "maidsafe", "safe_network");
        let result = repository
            .get_latest_asset_name(&AssetType::Testnet, "x86_64-unknown-linux-musl")
            .await;

        releases_list_mock.assert();
        release_by_tag_mock.assert();
        match result {
            Err(msg) => {
                assert_eq!(
                    msg.to_string(),
                    "Release sn_testnet-v0.1.15 has no asset for platform x86_64-unknown-linux-musl"
                );
                Ok(())
            }
            Ok(_) => Err(eyre!("This test case is expected to return an error")),
        }
    }

    #[test]
    fn get_versioned_asset_name_should_return_client_asset_name() -> Result<()> {
        let repository = GithubReleaseRepository::new("localhost", "maidsafe", "safe_network");
        let result = repository.get_versioned_asset_name(
            &AssetType::Client,
            "x86_64-unknown-linux-musl",
            "0.77.12",
        );
        assert_eq!(result, "safe-0.77.12-x86_64-unknown-linux-musl.tar.gz");
        Ok(())
    }

    #[test]
    fn get_versioned_asset_name_should_return_node_asset_name() -> Result<()> {
        let repository = GithubReleaseRepository::new("localhost", "maidsafe", "safe_network");
        let result = repository.get_versioned_asset_name(
            &AssetType::Node,
            "x86_64-unknown-linux-musl",
            "0.83.10",
        );
        assert_eq!(result, "safenode-0.83.10-x86_64-unknown-linux-musl.tar.gz");
        Ok(())
    }

    #[test]
    fn get_versioned_asset_name_should_return_testnet_asset_name() -> Result<()> {
        let repository = GithubReleaseRepository::new("localhost", "maidsafe", "safe_network");
        let result = repository.get_versioned_asset_name(
            &AssetType::Testnet,
            "x86_64-unknown-linux-musl",
            "0.1.14",
        );
        assert_eq!(result, "testnet-0.1.14-x86_64-unknown-linux-musl.tar.gz");
        Ok(())
    }
}
