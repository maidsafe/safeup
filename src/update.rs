use crate::install::{AssetType, Settings};
use semver::Version;
use std::cmp::Ordering;

use color_eyre::{eyre::eyre, Help, Result};

#[derive(Clone, Debug)]
pub enum UpdateAssessmentResult {
    PerformUpdate,
    NoPreviousInstallation,
    AtLatestVersion,
}

/// Determine whether to perform an upgrade for the component.
///
/// The process is:
/// * If we have no previous installation of a component, no upgrade will be performed.
/// * If the latest version number is less than the current version number, something is wrong
///   there, so we return an error and the caller can advise the user to consider reinstalling.
/// * Otherwise, if there is a newer version available, we'll perform the upgrade.
pub fn perform_update_assessment(
    asset_type: &AssetType,
    latest_version: &str,
    settings: &Settings,
) -> Result<UpdateAssessmentResult> {
    if !settings.is_installed(asset_type) {
        return Ok(UpdateAssessmentResult::NoPreviousInstallation);
    }
    match compare_versions(latest_version, &settings.get_installed_version(asset_type))? {
        Ordering::Equal => Ok(UpdateAssessmentResult::AtLatestVersion),
        Ordering::Less => Err(eyre!(
            "The latest version is less than the current version of your binary."
        )
        .suggestion("You may want to remove your safeup.conf and install safeup again.")),
        Ordering::Greater => Ok(UpdateAssessmentResult::PerformUpdate),
    }
}

fn compare_versions(version_a: &str, version_b: &str) -> Result<Ordering> {
    let v1 = Version::parse(version_a.strip_prefix('v').unwrap_or(version_a))?;
    let v2 = Version::parse(version_b.strip_prefix('v').unwrap_or(version_b))?;
    Ok(v1.cmp(&v2))
}

#[cfg(test)]
mod test {
    use super::{perform_update_assessment, UpdateAssessmentResult};
    use crate::install::{AssetType, Settings};
    use color_eyre::{eyre::eyre, Result};
    use std::path::PathBuf;

    #[test]
    fn perform_upgrade_assessment_should_indicate_no_previous_installation() -> Result<()> {
        let settings = Settings {
            safe_path: PathBuf::new(),
            safe_version: String::new(),
            safenode_path: PathBuf::from("/home/chris/.local/bin/safenode"),
            safenode_version: "v0.83.13".to_string(),
            testnet_path: PathBuf::from("/home/chris/.local/bin/testnet"),
            testnet_version: "v0.3.4".to_string(),
        };
        let decision = perform_update_assessment(&AssetType::Client, "v0.78.26", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::NoPreviousInstallation);

        let settings = Settings {
            safe_path: PathBuf::from("/home/chris/.local/safe"),
            safe_version: "v0.78.26".to_string(),
            safenode_path: PathBuf::new(),
            safenode_version: String::new(),
            testnet_path: PathBuf::from("/home/chris/.local/bin/testnet"),
            testnet_version: "v0.3.4".to_string(),
        };
        let decision = perform_update_assessment(&AssetType::Node, "v0.83.13", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::NoPreviousInstallation);

        let settings = Settings {
            safe_path: PathBuf::from("/home/chris/.local/safe"),
            safe_version: "v0.78.26".to_string(),
            safenode_path: PathBuf::from("/home/chris/.local/bin/safenode"),
            safenode_version: "v0.83.13".to_string(),
            testnet_path: PathBuf::new(),
            testnet_version: String::new(),
        };
        let decision = perform_update_assessment(&AssetType::Testnet, "v0.3.4", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::NoPreviousInstallation);

        Ok(())
    }

    #[test]
    fn perform_upgrade_assessment_should_indicate_we_are_at_latest_version() -> Result<()> {
        let settings = Settings {
            safe_path: PathBuf::from("/home/chris/.local/safe"),
            safe_version: "v0.78.26".to_string(),
            safenode_path: PathBuf::from("/home/chris/.local/bin/safenode"),
            safenode_version: "v0.83.13".to_string(),
            testnet_path: PathBuf::from("/home/chris/.local/bin/testnet"),
            testnet_version: "v0.3.4".to_string(),
        };

        let decision = perform_update_assessment(&AssetType::Client, "v0.78.26", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::AtLatestVersion);

        let decision = perform_update_assessment(&AssetType::Node, "v0.83.13", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::AtLatestVersion);

        let decision = perform_update_assessment(&AssetType::Testnet, "v0.3.4", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::AtLatestVersion);

        Ok(())
    }

    #[test]
    fn perform_upgrade_assessment_latest_version_is_less_than_current_should_return_error(
    ) -> Result<()> {
        let settings = Settings {
            safe_path: PathBuf::from("/home/chris/.local/safe"),
            safe_version: "v0.78.26".to_string(),
            safenode_path: PathBuf::from("/home/chris/.local/bin/safenode"),
            safenode_version: "v0.83.13".to_string(),
            testnet_path: PathBuf::from("/home/chris/.local/bin/testnet"),
            testnet_version: "v0.3.4".to_string(),
        };

        let result = perform_update_assessment(&AssetType::Client, "v0.76.0", &settings);
        match result {
            Ok(_) => return Err(eyre!("this test should return an error")),
            Err(e) => assert_eq!(
                "The latest version is less than the current version of your binary.",
                e.to_string()
            ),
        }

        let result = perform_update_assessment(&AssetType::Node, "v0.82.0", &settings);
        match result {
            Ok(_) => return Err(eyre!("this test should return an error")),
            Err(e) => assert_eq!(
                "The latest version is less than the current version of your binary.",
                e.to_string()
            ),
        }

        let result = perform_update_assessment(&AssetType::Node, "v0.2.0", &settings);
        match result {
            Ok(_) => return Err(eyre!("this test should return an error")),
            Err(e) => assert_eq!(
                "The latest version is less than the current version of your binary.",
                e.to_string()
            ),
        }
        Ok(())
    }

    #[test]
    fn perform_upgrade_assessment_should_perform_update_when_latest_patch_version_is_greater(
    ) -> Result<()> {
        let settings = Settings {
            safe_path: PathBuf::from("/home/chris/.local/safe"),
            safe_version: "v0.78.26".to_string(),
            safenode_path: PathBuf::from("/home/chris/.local/bin/safenode"),
            safenode_version: "v0.83.13".to_string(),
            testnet_path: PathBuf::from("/home/chris/.local/bin/testnet"),
            testnet_version: "v0.3.4".to_string(),
        };

        let decision = perform_update_assessment(&AssetType::Client, "v0.78.27", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate);

        let decision = perform_update_assessment(&AssetType::Node, "v0.83.14", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate);

        let decision = perform_update_assessment(&AssetType::Testnet, "v0.3.5", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate);

        Ok(())
    }

    #[test]
    fn perform_upgrade_assessment_should_perform_update_when_latest_minor_version_is_greater(
    ) -> Result<()> {
        let settings = Settings {
            safe_path: PathBuf::from("/home/chris/.local/safe"),
            safe_version: "v0.78.26".to_string(),
            safenode_path: PathBuf::from("/home/chris/.local/bin/safenode"),
            safenode_version: "v0.83.13".to_string(),
            testnet_path: PathBuf::from("/home/chris/.local/bin/testnet"),
            testnet_version: "v0.3.4".to_string(),
        };

        let decision = perform_update_assessment(&AssetType::Client, "v0.79.0", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate);

        let decision = perform_update_assessment(&AssetType::Node, "v0.84.0", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate);

        let decision = perform_update_assessment(&AssetType::Testnet, "v0.4.0", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate);

        Ok(())
    }

    #[test]
    fn perform_upgrade_assessment_should_perform_update_when_latest_major_version_is_greater(
    ) -> Result<()> {
        let settings = Settings {
            safe_path: PathBuf::from("/home/chris/.local/safe"),
            safe_version: "v0.78.26".to_string(),
            safenode_path: PathBuf::from("/home/chris/.local/bin/safenode"),
            safenode_version: "v0.83.13".to_string(),
            testnet_path: PathBuf::from("/home/chris/.local/bin/testnet"),
            testnet_version: "v0.3.4".to_string(),
        };

        let decision = perform_update_assessment(&AssetType::Client, "v1.0.0", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate);

        let decision = perform_update_assessment(&AssetType::Node, "v1.0.0", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate);

        let decision = perform_update_assessment(&AssetType::Testnet, "v1.0.0", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate);

        Ok(())
    }

    #[test]
    fn perform_upgrade_assessment_should_not_error_when_versions_have_no_leading_v() -> Result<()> {
        let settings = Settings {
            safe_path: PathBuf::from("/home/chris/.local/safe"),
            safe_version: "0.78.26".to_string(),
            safenode_path: PathBuf::from("/home/chris/.local/bin/safenode"),
            safenode_version: "0.83.13".to_string(),
            testnet_path: PathBuf::from("/home/chris/.local/bin/testnet"),
            testnet_version: "0.3.4".to_string(),
        };

        let decision = perform_update_assessment(&AssetType::Client, "0.78.27", &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate);

        Ok(())
    }
}
