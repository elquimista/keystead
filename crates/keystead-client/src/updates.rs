//! Whether a newer Keystead is out: this repository's latest GitHub release, if it's newer
//! than the running app and has the Mac app attached. Nothing is downloaded or installed
//! here; the app points the person at the release's page.

use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;

/// The latest release: GitHub leaves out drafts and pre-releases.
pub const LATEST_RELEASE: &str = "https://api.github.com/repos/elquimista/keystead/releases/latest";

/// Where release pages and their files are; links elsewhere are refused.
const RELEASES: &str = "https://github.com/elquimista/keystead/releases/";

/// A release newer than the running app, with the Mac app attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// "0.14.0".
    pub version: String,
    /// The release's page: what changed, and how to install it.
    pub page: String,
    /// The Mac app's zip.
    pub download: String,
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// Asks GitHub for the latest release, sending only `user_agent` (which GitHub requires),
/// and returns it if it's newer than `current` and has the Mac app. Blocks on the network.
pub fn check(current: &str, user_agent: &str) -> anyhow::Result<Option<Update>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .build();
    let response = agent
        .get(LATEST_RELEASE)
        .set("Accept", "application/vnd.github+json")
        .set("User-Agent", user_agent)
        .call();
    let release: Release = match response {
        Ok(response) => response
            .into_json()
            .context("GitHub's answer about releases wasn't readable")?,
        // No releases yet.
        Err(ureq::Error::Status(404, _)) => return Ok(None),
        Err(ureq::Error::Status(403 | 429, _)) => {
            bail!("GitHub is limiting how often it's asked; try again in an hour")
        }
        Err(ureq::Error::Status(code, _)) => bail!("GitHub answered {code}"),
        Err(ureq::Error::Transport(error)) => bail!("couldn't reach GitHub: {error}"),
    };
    newer(current, &release)
}

/// The release, if it's a final release newer than `current` with the Mac app attached as
/// `Keystead-<version>.zip`, and its links are this repository's.
fn newer(current: &str, release: &Release) -> anyhow::Result<Option<Update>> {
    if release.draft || release.prerelease {
        return Ok(None);
    }
    let version = release.tag_name.trim_start_matches('v');
    let (Some(latest), Some(running)) = (numbers(version), numbers(current)) else {
        return Ok(None);
    };
    if latest <= running {
        return Ok(None);
    }
    let zip = format!("Keystead-{version}.zip");
    let Some(asset) = release.assets.iter().find(|asset| asset.name == zip) else {
        // Its Mac app isn't attached (yet): nothing to point anyone at.
        return Ok(None);
    };
    let download = format!("{RELEASES}download/");
    if !release.html_url.starts_with(RELEASES) || !asset.browser_download_url.starts_with(&download)
    {
        bail!("GitHub's answer about releases pointed somewhere unexpected");
    }
    Ok(Some(Update {
        version: version.to_owned(),
        page: release.html_url.clone(),
        download: asset.browser_download_url.clone(),
    }))
}

/// "0.13.1" as numbers to compare; None for anything else, like "0.14.0-rc.1".
fn numbers(version: &str) -> Option<Vec<u64>> {
    let parts = version
        .split('.')
        .map(|part| part.parse().ok())
        .collect::<Option<Vec<u64>>>()?;
    (!parts.is_empty()).then_some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, assets: &[&str]) -> Release {
        serde_json::from_value(serde_json::json!({
            "tag_name": tag,
            "html_url": format!("https://github.com/elquimista/keystead/releases/tag/{tag}"),
            "draft": false,
            "prerelease": false,
            "assets": assets.iter().map(|name| serde_json::json!({
                "name": name,
                "browser_download_url":
                    format!("https://github.com/elquimista/keystead/releases/download/{tag}/{name}"),
            })).collect::<Vec<_>>(),
        }))
        .unwrap()
    }

    #[test]
    fn a_newer_release_with_the_mac_app_is_an_update() {
        let update = newer(
            "0.13.1",
            &release(
                "v0.14.0",
                &["Keystead-0.14.0.zip.sha256", "Keystead-0.14.0.zip"],
            ),
        )
        .unwrap()
        .unwrap();
        assert_eq!(update.version, "0.14.0");
        assert_eq!(
            update.page,
            "https://github.com/elquimista/keystead/releases/tag/v0.14.0"
        );
        assert_eq!(
            update.download,
            "https://github.com/elquimista/keystead/releases/download/v0.14.0/Keystead-0.14.0.zip"
        );
    }

    #[test]
    fn versions_compare_as_numbers() {
        let zip = |v: &str| format!("Keystead-{v}.zip");
        assert!(
            newer("0.9.0", &release("v0.10.0", &[&zip("0.10.0")]))
                .unwrap()
                .is_some()
        );
        assert!(
            newer("0.13.1", &release("v0.13.10", &[&zip("0.13.10")]))
                .unwrap()
                .is_some()
        );
        assert!(
            newer("0.13.1", &release("v1.0.0", &[&zip("1.0.0")]))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn the_same_or_an_older_release_is_not() {
        assert_eq!(
            newer("0.13.1", &release("v0.13.1", &["Keystead-0.13.1.zip"])).unwrap(),
            None
        );
        assert_eq!(
            newer("0.14.0", &release("v0.13.1", &["Keystead-0.13.1.zip"])).unwrap(),
            None
        );
    }

    #[test]
    fn a_release_without_the_mac_app_is_not() {
        assert_eq!(newer("0.13.1", &release("v0.14.0", &[])).unwrap(), None);
        assert_eq!(
            newer("0.13.1", &release("v0.14.0", &["Keystead-0.13.1.zip"])).unwrap(),
            None
        );
    }

    #[test]
    fn drafts_and_pre_releases_are_not() {
        let mut draft = release("v0.14.0", &["Keystead-0.14.0.zip"]);
        draft.draft = true;
        assert_eq!(newer("0.13.1", &draft).unwrap(), None);
        let mut pre = release("v0.14.0", &["Keystead-0.14.0.zip"]);
        pre.prerelease = true;
        assert_eq!(newer("0.13.1", &pre).unwrap(), None);
        assert_eq!(
            newer(
                "0.13.1",
                &release("v0.14.0-rc.1", &["Keystead-0.14.0-rc.1.zip"])
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn links_elsewhere_are_refused() {
        let mut elsewhere = release("v0.14.0", &["Keystead-0.14.0.zip"]);
        elsewhere.html_url = "https://example.com/keystead".into();
        assert!(newer("0.13.1", &elsewhere).is_err());
        let mut download = release("v0.14.0", &["Keystead-0.14.0.zip"]);
        download.assets[0].browser_download_url = "https://example.com/Keystead-0.14.0.zip".into();
        assert!(newer("0.13.1", &download).is_err());
    }

    #[test]
    fn reads_githubs_answer() {
        let answer = r#"{"tag_name":"v0.14.0","html_url":"https://github.com/elquimista/keystead/releases/tag/v0.14.0",
            "draft":false,"prerelease":false,"name":"Keystead 0.14.0","body":"Notes",
            "assets":[{"name":"Keystead-0.14.0.zip","size":9804619,
            "browser_download_url":"https://github.com/elquimista/keystead/releases/download/v0.14.0/Keystead-0.14.0.zip"}]}"#;
        let release: Release = serde_json::from_str(answer).unwrap();
        assert_eq!(
            newer("0.13.1", &release).unwrap().unwrap().version,
            "0.14.0"
        );
    }

    /// Asks GitHub itself: `cargo test -p keystead-client updates -- --ignored`. Needs the
    /// network, and a release with the Mac app newer than 0.13.0 (0.13.1 was the first).
    #[test]
    #[ignore = "asks GitHub"]
    fn asks_github() {
        let update = check("0.13.0", "Keystead-test").unwrap().unwrap();
        assert!(
            update
                .download
                .ends_with(&format!("/Keystead-{}.zip", update.version))
        );
        assert_eq!(check(&update.version, "Keystead-test").unwrap(), None);
    }
}
