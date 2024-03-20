use crate::install::{AssetType, Settings};
use semver::Version;
use std::cmp::Ordering;
use std::path::PathBuf;

use color_eyre::{eyre::eyre, Help, Result};

#[derive(Clone, Debug)]
pub enum UpdateAssessmentResult {
    PerformUpdate(PathBuf),
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
    latest_version: &Version,
    settings: &Settings,
) -> Result<UpdateAssessmentResult> {
    if let Some((installed_path, installed_version)) = settings.get_install_details(asset_type) {
        println!("Current version of {asset_type} is {installed_version}");
        match latest_version.cmp(&installed_version) {
            Ordering::Equal => return Ok(UpdateAssessmentResult::AtLatestVersion),
            Ordering::Less => {
                return Err(eyre!(
                    "The latest version is less than the current version of your binary."
                )
                .suggestion("You may want to remove your safeup.conf and install safeup again."))
            }
            Ordering::Greater => return Ok(UpdateAssessmentResult::PerformUpdate(installed_path)),
        }
    }
    Ok(UpdateAssessmentResult::NoPreviousInstallation)
}

#[cfg(test)]
mod test {
    use super::{perform_update_assessment, UpdateAssessmentResult};
    use crate::install::{AssetType, Settings};
    use color_eyre::{eyre::eyre, Result};
    use semver::Version;
    use std::path::PathBuf;

    #[test]
    fn perform_upgrade_assessment_should_indicate_no_previous_installation() -> Result<()> {
        let settings = Settings {
            safe_path: None,
            safe_version: None,
            safenode_path: Some(PathBuf::from("/home/chris/.local/bin/safenode")),
            safenode_version: Some(Version::new(0, 83, 13)),
            safenode_manager_path: Some(PathBuf::from("/home/chris/.local/bin/safenode-manager")),
            safenode_manager_version: Some(Version::new(0, 1, 8)),
        };
        let decision =
            perform_update_assessment(&AssetType::Client, &Version::new(0, 78, 26), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::NoPreviousInstallation);

        let settings = Settings {
            safe_path: Some(PathBuf::from("/home/chris/.local/safe")),
            safe_version: Some(Version::new(0, 78, 26)),
            safenode_path: None,
            safenode_version: None,
            safenode_manager_path: Some(PathBuf::from("/home/chris/.local/bin/safenode-manager")),
            safenode_manager_version: Some(Version::new(0, 1, 8)),
        };
        let decision =
            perform_update_assessment(&AssetType::Node, &Version::new(0, 83, 13), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::NoPreviousInstallation);

        let settings = Settings {
            safe_path: Some(PathBuf::from("/home/chris/.local/safe")),
            safe_version: Some(Version::new(0, 78, 26)),
            safenode_path: Some(PathBuf::from("/home/chris/.local/bin/safenode")),
            safenode_version: Some(Version::new(0, 83, 13)),
            safenode_manager_path: None,
            safenode_manager_version: None,
        };
        let decision =
            perform_update_assessment(&AssetType::NodeManager, &Version::new(0, 1, 8), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::NoPreviousInstallation);

        Ok(())
    }

    #[test]
    fn perform_upgrade_assessment_should_indicate_we_are_at_latest_version() -> Result<()> {
        let settings = Settings {
            safe_path: Some(PathBuf::from("/home/chris/.local/safe")),
            safe_version: Some(Version::new(0, 78, 26)),
            safenode_path: Some(PathBuf::from("/home/chris/.local/bin/safenode")),
            safenode_version: Some(Version::new(0, 83, 13)),
            safenode_manager_path: Some(PathBuf::from("/home/chris/.local/bin/safenode-manager")),
            safenode_manager_version: Some(Version::new(0, 1, 8)),
        };

        let decision =
            perform_update_assessment(&AssetType::Client, &Version::new(0, 78, 26), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::AtLatestVersion);

        let decision =
            perform_update_assessment(&AssetType::Node, &Version::new(0, 83, 13), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::AtLatestVersion);

        let decision =
            perform_update_assessment(&AssetType::NodeManager, &Version::new(0, 1, 8), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::AtLatestVersion);

        Ok(())
    }

    #[test]
    fn perform_upgrade_assessment_latest_version_is_less_than_current_should_return_error(
    ) -> Result<()> {
        let settings = Settings {
            safe_path: Some(PathBuf::from("/home/chris/.local/safe")),
            safe_version: Some(Version::new(0, 78, 26)),
            safenode_path: Some(PathBuf::from("/home/chris/.local/bin/safenode")),
            safenode_version: Some(Version::new(0, 83, 13)),
            safenode_manager_path: Some(PathBuf::from("/home/chris/.local/bin/safenode-manager")),
            safenode_manager_version: Some(Version::new(0, 1, 8)),
        };

        let result =
            perform_update_assessment(&AssetType::Client, &Version::new(0, 76, 0), &settings);
        match result {
            Ok(_) => return Err(eyre!("this test should return an error")),
            Err(e) => assert_eq!(
                "The latest version is less than the current version of your binary.",
                e.to_string()
            ),
        }

        let result =
            perform_update_assessment(&AssetType::Node, &Version::new(0, 81, 0), &settings);
        match result {
            Ok(_) => return Err(eyre!("this test should return an error")),
            Err(e) => assert_eq!(
                "The latest version is less than the current version of your binary.",
                e.to_string()
            ),
        }

        let result =
            perform_update_assessment(&AssetType::NodeManager, &Version::new(0, 1, 7), &settings);
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
            safe_path: Some(PathBuf::from("/home/chris/.local/safe")),
            safe_version: Some(Version::new(0, 78, 26)),
            safenode_path: Some(PathBuf::from("/home/chris/.local/bin/safenode")),
            safenode_version: Some(Version::new(0, 83, 13)),
            safenode_manager_path: Some(PathBuf::from("/home/chris/.local/bin/safenode-manager")),
            safenode_manager_version: Some(Version::new(0, 1, 7)),
        };

        let decision =
            perform_update_assessment(&AssetType::Client, &Version::new(0, 78, 27), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate(_));

        let decision =
            perform_update_assessment(&AssetType::Node, &Version::new(0, 83, 14), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate(_));

        let decision =
            perform_update_assessment(&AssetType::NodeManager, &Version::new(0, 1, 8), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate(_));

        Ok(())
    }

    #[test]
    fn perform_upgrade_assessment_should_perform_update_when_latest_minor_version_is_greater(
    ) -> Result<()> {
        let settings = Settings {
            safe_path: Some(PathBuf::from("/home/chris/.local/safe")),
            safe_version: Some(Version::new(0, 78, 26)),
            safenode_path: Some(PathBuf::from("/home/chris/.local/bin/safenode")),
            safenode_version: Some(Version::new(0, 83, 13)),
            safenode_manager_path: Some(PathBuf::from("/home/chris/.local/bin/safenode-manager")),
            safenode_manager_version: Some(Version::new(0, 1, 7)),
        };

        let decision =
            perform_update_assessment(&AssetType::Client, &Version::new(0, 79, 0), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate(_));

        let decision =
            perform_update_assessment(&AssetType::Node, &Version::new(0, 84, 0), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate(_));

        let decision =
            perform_update_assessment(&AssetType::NodeManager, &Version::new(0, 2, 0), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate(_));

        Ok(())
    }

    #[test]
    fn perform_upgrade_assessment_should_perform_update_when_latest_major_version_is_greater(
    ) -> Result<()> {
        let settings = Settings {
            safe_path: Some(PathBuf::from("/home/chris/.local/safe")),
            safe_version: Some(Version::new(0, 78, 26)),
            safenode_path: Some(PathBuf::from("/home/chris/.local/bin/safenode")),
            safenode_version: Some(Version::new(0, 83, 13)),
            safenode_manager_path: Some(PathBuf::from("/home/chris/.local/bin/safenode-manager")),
            safenode_manager_version: Some(Version::new(0, 1, 7)),
        };

        let decision =
            perform_update_assessment(&AssetType::Client, &Version::new(1, 0, 0), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate(_));

        let decision =
            perform_update_assessment(&AssetType::Node, &Version::new(1, 0, 0), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate(_));

        let decision =
            perform_update_assessment(&AssetType::NodeManager, &Version::new(1, 0, 0), &settings)?;
        assert_matches!(decision, UpdateAssessmentResult::PerformUpdate(_));

        Ok(())
    }
}
