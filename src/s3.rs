// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use color_eyre::{eyre::eyre, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Write;
use std::path::PathBuf;

pub struct S3AssetRepository {
    pub base_url: String,
}

impl S3AssetRepository {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
        }
    }

    /// Downloads the specified binary archive from S3 to the path specified.
    ///
    /// # Arguments
    ///
    /// * `asset_name` - The name of the binary archive to download from the S3 bucket.
    /// * `dest_path` - The path where the archive will be saved.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an `eyre::Report` if an error occurs during the download process. Possible error
    /// conditions include network errors, I/O errors, and missing or invalid data in the response
    /// body.
    pub async fn download_asset(&self, asset_name: &str, dest_path: &PathBuf) -> Result<()> {
        let client = reqwest::Client::new();
        let mut response = client
            .get(format!("{}/{}", self.base_url, asset_name))
            .send()
            .await?;
        let content_len = response
            .content_length()
            .ok_or_else(|| eyre!("Could not determine content length for asset"))?;

        let pb = ProgressBar::new(content_len);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes}")?
                .progress_chars("#>-"),
        );

        let mut downloaded_file = std::fs::File::create(dest_path)?;
        let mut bytes_downloaded = 0;
        while let Some(chunk) = response.chunk().await? {
            downloaded_file.write_all(&chunk)?;
            bytes_downloaded += chunk.len() as u64;
            pb.set_position(bytes_downloaded);
        }
        pb.finish_with_message("{bytes_downloaded}");
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::S3AssetRepository;
    use assert_fs::prelude::*;
    use color_eyre::Result;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use httpmock::prelude::*;
    use predicates::prelude::*;
    use std::fs::File;

    #[tokio::test]
    async fn download_asset_should_download_the_asset_to_the_specified_path() -> Result<()> {
        let tmp_data_path = assert_fs::TempDir::new()?;
        let safe_archive = tmp_data_path.child("safe.tar.gz");
        let downloaded_safe_archive =
            tmp_data_path.child("safe-0.72.1-x86_64-unknown-linux-musl.tar.gz");
        let fake_safe_bin = tmp_data_path.child("safe");
        fake_safe_bin.write_binary(b"fake code")?;

        let mut fake_safe_bin_file = File::open(fake_safe_bin.path())?;
        let gz_encoder = GzEncoder::new(File::create(safe_archive.path())?, Compression::default());
        let mut builder = tar::Builder::new(gz_encoder);
        builder.append_file("safe", &mut fake_safe_bin_file)?;
        builder.into_inner()?;
        let safe_archive_metadata = std::fs::metadata(safe_archive.path())?;

        let server = MockServer::start();
        let download_asset_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/safe-0.72.1-x86_64-unknown-linux-musl.tar.gz");
            then.status(200)
                .header("Content-Length", safe_archive_metadata.len().to_string())
                .header("Content-Type", "application/gzip")
                .body_from_file(safe_archive.path().to_str().unwrap());
        });

        let repository = S3AssetRepository::new(&server.base_url());
        repository
            .download_asset(
                "safe-0.72.1-x86_64-unknown-linux-musl.tar.gz",
                &downloaded_safe_archive.path().to_path_buf(),
            )
            .await?;

        download_asset_mock.assert();
        downloaded_safe_archive.assert(predicate::path::is_file());
        let downloaded_file_metadata = std::fs::metadata(downloaded_safe_archive.path())?;
        assert_eq!(safe_archive_metadata.len(), downloaded_file_metadata.len());

        Ok(())
    }
}
