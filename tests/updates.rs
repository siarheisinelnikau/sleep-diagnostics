use anyhow::bail;
use sha2::{Digest, Sha256};
use sleep_diagnostics::update::*;

fn binary() -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&128u32.to_le_bytes());
    bytes[128..132].copy_from_slice(b"PE\0\0");
    let machine: u16 = if cfg!(target_arch = "x86_64") {
        0x8664
    } else if cfg!(target_arch = "aarch64") {
        0xaa64
    } else {
        0x14c
    };
    bytes[132..134].copy_from_slice(&machine.to_le_bytes());
    bytes
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn release(version: &str) -> Release {
    let name = format!("SleepDiagnostics-v{version}.exe");
    Release {
        tag_name: format!("v{version}"),
        draft: false,
        prerelease: false,
        assets: vec![Asset {
            browser_download_url: format!(
                "https://github.com/{REPOSITORY}/releases/download/v{version}/{name}"
            ),
            name,
            size: 1024,
            digest: Some(format!("sha256:{}", hash(&binary()))),
        }],
    }
}

#[test]
fn semantic_versions_are_compared_as_versions() {
    assert!(
        select_release(release("0.10.0"), "0.9.0")
            .unwrap()
            .is_some()
    );
    assert!(
        select_release(release("0.9.0"), "0.10.0")
            .unwrap()
            .is_none()
    );
    assert!(select_release(release("0.1.0"), "0.1.0").unwrap().is_none());
}
#[test]
fn unstable_missing_or_foreign_assets_are_rejected() {
    let mut r = release("0.2.0");
    r.draft = true;
    assert!(select_release(r, "0.1.0").is_err());
    let mut r = release("0.2.0");
    r.prerelease = true;
    assert!(select_release(r, "0.1.0").is_err());
    let mut r = release("0.2.0");
    r.assets.clear();
    assert!(select_release(r, "0.1.0").is_err());
    let mut r = release("0.2.0");
    r.assets[0].browser_download_url = "https://example.com/update.exe".into();
    assert!(select_release(r, "0.1.0").is_err());
    let mut r = release("0.2.0");
    r.assets[0].digest = None;
    assert!(select_release(r, "0.1.0").is_err());
    let mut r = release("0.2.0");
    r.assets[0].name = "SleepDiagnostics-v0.2.0-arm64.exe".into();
    assert!(select_release(r, "0.1.0").is_err());
}
#[test]
fn checksums_must_identify_the_exact_asset() {
    let h = hash(&binary());
    assert_eq!(
        parse_checksum(
            &format!("{h}  SleepDiagnostics-v0.2.0.exe\n"),
            "SleepDiagnostics-v0.2.0.exe"
        )
        .unwrap(),
        h
    );
    assert!(parse_checksum(&format!("{h} other.exe"), "SleepDiagnostics-v0.2.0.exe").is_err());
    assert!(
        parse_checksum(
            "bad  SleepDiagnostics-v0.2.0.exe",
            "SleepDiagnostics-v0.2.0.exe"
        )
        .is_err()
    );
}
#[test]
fn corrupt_or_wrong_architecture_binary_is_never_accepted() {
    let good = binary();
    verify_binary(&good, &hash(&good)).unwrap();
    let mut corrupt = good.clone();
    corrupt[999] = 1;
    assert!(verify_binary(&corrupt, &hash(&good)).is_err());
    let mut wrong = good.clone();
    wrong[132] = 0;
    wrong[133] = 0;
    assert!(verify_binary(&wrong, &hash(&wrong)).is_err());
    assert!(verify_binary(b"MZ", &hash(b"MZ")).is_err());
    let mut malformed = good;
    malformed[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(verify_binary(&malformed, &hash(&malformed)).is_err());
}
fn plan(root: &std::path::Path) -> InstallPlan {
    let target = root.join("app.exe");
    let staged = root.join("staged.exe");
    std::fs::write(&target, b"old executable").unwrap();
    std::fs::write(&staged, binary()).unwrap();
    InstallPlan {
        target,
        staged,
        backup: root.join("previous.exe"),
        helper: root.join("helper.exe"),
        sha256: hash(&binary()),
        parent_pid: 1,
        parent_creation: 1,
    }
}
#[test]
fn failed_restart_rolls_back_without_touching_history_or_settings() {
    let dir = tempfile::tempdir().unwrap();
    let p = plan(dir.path());
    let settings = dir.path().join("settings.json");
    std::fs::write(&settings, "user preferences").unwrap();
    assert!(replace_and_launch(&p, |_| bail!("synthetic launch failure")).is_err());
    assert_eq!(std::fs::read(&p.target).unwrap(), b"old executable");
    assert_eq!(
        std::fs::read_to_string(settings).unwrap(),
        "user preferences"
    );
}
#[test]
fn success_keeps_a_recovery_copy_and_uses_the_existing_install_path() {
    let dir = tempfile::tempdir().unwrap();
    let p = plan(dir.path());
    replace_and_launch(&p, |target| {
        assert_eq!(target, p.target);
        Ok(())
    })
    .unwrap();
    assert_eq!(std::fs::read(&p.target).unwrap(), binary());
    assert_eq!(std::fs::read(&p.backup).unwrap(), b"old executable");
}
#[test]
fn failed_integrity_check_leaves_installed_binary_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = plan(dir.path());
    p.sha256 = "0".repeat(64);
    assert!(replace_and_launch(&p, |_| panic!("must not launch")).is_err());
    assert_eq!(std::fs::read(&p.target).unwrap(), b"old executable");
    assert!(!p.backup.exists());
}

#[test]
fn cleanup_removes_only_its_finished_helper_and_keeps_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = plan(dir.path());
    let prefix = ".SleepDiagnostics-123-456";
    p.helper = dir.path().join(format!("{prefix}-helper.exe"));
    p.backup = dir.path().join(format!("{prefix}-previous.exe"));
    let manifest = dir.path().join(format!("{prefix}-plan.json"));
    replace_and_launch(&p, |_| Ok(())).unwrap();
    std::fs::write(&p.helper, b"helper copy").unwrap();
    std::fs::write(&manifest, serde_json::to_vec(&p).unwrap()).unwrap();
    cleanup_completed_install(&manifest, &p.target).unwrap();
    assert!(!manifest.exists() && !p.helper.exists());
    assert_eq!(std::fs::read(&p.backup).unwrap(), b"old executable");
    assert_eq!(std::fs::read(&p.target).unwrap(), binary());
}

#[test]
fn cleanup_rejects_a_helper_outside_its_transaction_directory() {
    let dir = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let mut p = plan(dir.path());
    p.helper = other.path().join(".SleepDiagnostics-123-helper.exe");
    std::fs::write(&p.helper, b"unrelated").unwrap();
    let manifest = dir.path().join(".SleepDiagnostics-123-plan.json");
    std::fs::write(&manifest, serde_json::to_vec(&p).unwrap()).unwrap();
    assert!(cleanup_completed_install(&manifest, &p.target).is_err());
    assert_eq!(std::fs::read(&p.helper).unwrap(), b"unrelated");
}
