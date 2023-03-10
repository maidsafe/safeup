// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::install::AssetType;
use color_eyre::{eyre::eyre, Result};
use reqwest::Client;
use serde_json::Value;

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
        asset_type: AssetType,
        platform: &str,
    ) -> Result<(String, String)> {
        let client = Client::new();
        let response = client
            .get(format!(
                "{}/repos/{}/{}/releases/latest",
                self.base_url, self.organisation_name, self.repository_name
            ))
            .header("User-Agent", "safeup")
            .send()
            .await?;
        let body = response.text().await?;

        let json: Value = serde_json::from_str(&body)?;
        let tag_name = json["tag_name"]
            .as_str()
            .ok_or_else(|| eyre!("Response body does not contain 'tag_name' value"))?;
        let version = self.get_version_from_tag_name(&asset_type, tag_name)?;

        let asset_name = match asset_type {
            AssetType::Client => format!("sn_cli-{version}-{platform}.tar.gz"),
            AssetType::Node => {
                format!("sn_node-{version}-{platform}.tar.gz")
            }
        };
        if self.release_has_asset(&json, &asset_name)? {
            return Ok((asset_name, version));
        }

        let msg = match asset_type {
            AssetType::Client => format!("Release has no client asset for platform {platform}"),
            AssetType::Node => format!("Release has no node asset for platform {platform}"),
        };

        Err(eyre!(msg))
    }

    fn release_has_asset(&self, json: &Value, asset_name: &str) -> Result<bool> {
        let assets = json["assets"]
            .as_array()
            .ok_or_else(|| eyre!("Response body does not contain 'asset' value"))?;
        let release_has_asset = assets.iter().any(|a| {
            if let Some(name) = a["name"].as_str() {
                name == asset_name
            } else {
                false
            }
        });
        Ok(release_has_asset)
    }

    fn get_version_from_tag_name(&self, asset_type: &AssetType, tag_name: &str) -> Result<String> {
        let mut parts = tag_name.split('-');
        let version = match asset_type {
            AssetType::Client => parts
                .last()
                .ok_or_else(|| eyre!("Could not parse version from tag_name"))?
                .to_string(),
            AssetType::Node => {
                parts.next();
                parts.next();
                parts.next();
                parts.next();
                parts.next();
                parts
                    .next()
                    .ok_or_else(|| eyre!("Could not parse version from tag_name"))?
                    .to_string()
            }
        };
        Ok(version)
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
        let response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("latest_release_response_body.json"),
        )?;
        let latest_release_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/latest");
            then.status(200)
                .header("server", "Github.com")
                .body(response_body);
        });

        let repository =
            GithubReleaseRepository::new(&server.base_url(), "maidsafe", "safe_network");
        let (asset_name, version) = repository
            .get_latest_asset_name(AssetType::Client, "x86_64-unknown-linux-musl")
            .await?;

        latest_release_mock.assert();
        assert_eq!(asset_name, "sn_cli-0.72.1-x86_64-unknown-linux-musl.tar.gz");
        assert_eq!(version, "0.72.1");
        Ok(())
    }

    #[tokio::test]
    async fn get_latest_asset_name_for_client_should_return_error_when_release_has_no_asset(
    ) -> Result<()> {
        let server = MockServer::start();
        let response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("release_with_no_assets_response_body.json"),
        )?;
        let latest_release_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/latest");
            then.status(200)
                .header("server", "Github.com")
                .body(response_body);
        });

        let repository =
            GithubReleaseRepository::new(&server.base_url(), "maidsafe", "safe_network");
        let result = repository
            .get_latest_asset_name(AssetType::Client, "x86_64-unknown-linux-musl")
            .await;

        latest_release_mock.assert();
        match result {
            Err(msg) => {
                assert_eq!(
                    msg.to_string(),
                    "Release has no client asset for platform x86_64-unknown-linux-musl"
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
        let response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("latest_release_response_body.json"),
        )?;
        let latest_release_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/latest");
            then.status(200)
                .header("server", "Github.com")
                .body(response_body);
        });

        let repository =
            GithubReleaseRepository::new(&server.base_url(), "maidsafe", "safe_network");
        let (asset_name, version) = repository
            .get_latest_asset_name(AssetType::Node, "x86_64-unknown-linux-musl")
            .await?;

        latest_release_mock.assert();
        assert_eq!(
            asset_name,
            "sn_node-0.77.6-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(version, "0.77.6");
        Ok(())
    }

    #[tokio::test]
    async fn get_latest_asset_name_for_node_should_return_error_when_release_has_no_asset(
    ) -> Result<()> {
        let server = MockServer::start();
        let response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("release_with_no_assets_response_body.json"),
        )?;
        let latest_release_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/latest");
            then.status(200)
                .header("server", "Github.com")
                .body(response_body);
        });

        let repository =
            GithubReleaseRepository::new(&server.base_url(), "maidsafe", "safe_network");
        let result = repository
            .get_latest_asset_name(AssetType::Node, "x86_64-unknown-linux-musl")
            .await;

        latest_release_mock.assert();
        match result {
            Err(msg) => {
                assert_eq!(
                    msg.to_string(),
                    "Release has no node asset for platform x86_64-unknown-linux-musl"
                );
                Ok(())
            }
            Ok(_) => Err(eyre!("This test case is expected to return an error")),
        }
    }

    #[tokio::test]
    async fn get_latest_asset_name_for_node_should_return_error_when_release_has_invalid_tag_name(
    ) -> Result<()> {
        let server = MockServer::start();
        let response_body = std::fs::read_to_string(
            std::path::Path::new("resources").join("release_with_invalid_tag_name.json"),
        )?;
        let latest_release_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/maidsafe/safe_network/releases/latest");
            then.status(200)
                .header("server", "Github.com")
                .body(response_body);
        });

        let repository =
            GithubReleaseRepository::new(&server.base_url(), "maidsafe", "safe_network");
        let result = repository
            .get_latest_asset_name(AssetType::Node, "x86_64-unknown-linux-musl")
            .await;

        latest_release_mock.assert();
        match result {
            Err(msg) => {
                assert_eq!(msg.to_string(), "Could not parse version from tag_name");
                Ok(())
            }
            Ok(_) => Err(eyre!("This test case is expected to return an error")),
        }
    }
}
