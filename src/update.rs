use anyhow::{Context, Result, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub const REPOSITORY: &str = "siarheisinelnikau/sleep-diagnostics";
pub const API: &str =
    "https://api.github.com/repos/siarheisinelnikau/sleep-diagnostics/releases/latest";
pub const MAX_DOWNLOAD: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub draft: bool,
    pub prerelease: bool,
    pub assets: Vec<Asset>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
    pub digest: Option<String>,
}
#[derive(Debug, Clone)]
pub struct AvailableUpdate {
    pub version: Version,
    pub binary: Asset,
    pub checksum: Option<Asset>,
    pub expected_sha256: Option<String>,
}

pub fn select_release(release: Release, installed: &str) -> Result<Option<AvailableUpdate>> {
    ensure!(
        !release.draft && !release.prerelease,
        "Stable release required"
    );
    let version = Version::parse(release.tag_name.trim_start_matches('v'))?;
    ensure!(
        version.pre.is_empty() && version.build.is_empty(),
        "Stable version required"
    );
    if version <= Version::parse(installed)? {
        return Ok(None);
    }
    let name = format!("SleepDiagnostics-v{version}.exe");
    let matching: Vec<_> = release.assets.iter().filter(|a| a.name == name).collect();
    ensure!(
        matching.len() == 1,
        "Compatible standalone executable is unavailable"
    );
    let binary = matching[0].clone();
    ensure!(
        binary.size >= 1024 && binary.size <= MAX_DOWNLOAD,
        "Invalid release asset size"
    );
    validate_url(&binary, &version)?;
    let expected_sha256 = binary
        .digest
        .as_deref()
        .and_then(|s| s.strip_prefix("sha256:"))
        .filter(|s| valid_hash(s))
        .map(str::to_lowercase);
    let checksum = release
        .assets
        .iter()
        .find(|a| a.name == format!("{name}.sha256"))
        .cloned();
    if let Some(checksum) = &checksum {
        validate_url(checksum, &version)?;
        ensure!(checksum.size < 4096, "Invalid checksum asset");
    }
    ensure!(
        expected_sha256.is_some() || checksum.is_some(),
        "A verified checksum is required"
    );
    Ok(Some(AvailableUpdate {
        version,
        binary,
        checksum,
        expected_sha256,
    }))
}

fn validate_url(asset: &Asset, version: &Version) -> Result<()> {
    ensure!(
        asset.browser_download_url
            == format!(
                "https://github.com/{REPOSITORY}/releases/download/v{version}/{}",
                asset.name
            ),
        "Asset is outside the canonical release"
    );
    Ok(())
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn agent(timeout: u64) -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(Duration::from_secs(timeout)))
        .max_redirects(5)
        .build()
        .into()
}

pub fn check() -> Result<Option<AvailableUpdate>> {
    let mut response = agent(20).get(API).header("User-Agent", concat!("SleepDiagnostics/", env!("CARGO_PKG_VERSION")))
        .header("Accept", "application/vnd.github+json").call()
        .context("Repository or release unavailable; network access or GitHub rate limits may also prevent checking")?;
    let json = response
        .body_mut()
        .with_config()
        .limit(2 * 1024 * 1024)
        .read_to_vec()?;
    select_release(serde_json::from_slice(&json)?, env!("CARGO_PKG_VERSION"))
}

pub fn parse_checksum(text: &str, filename: &str) -> Result<String> {
    let mut parts = text.split_whitespace();
    let hash = parts.next().context("Missing SHA-256")?;
    let name = parts.next().unwrap_or("").trim_start_matches('*');
    ensure!(
        valid_hash(hash) && name == filename && parts.next().is_none(),
        "Invalid checksum entry"
    );
    Ok(hash.to_lowercase())
}

pub fn verify_binary(bytes: &[u8], expected: &str) -> Result<()> {
    ensure!(
        valid_hash(expected) && format!("{:x}", Sha256::digest(bytes)) == expected.to_lowercase(),
        "Update checksum mismatch"
    );
    ensure!(
        bytes.len() >= 256 && bytes.starts_with(b"MZ"),
        "Update is not a Windows executable"
    );
    let offset = u32::from_le_bytes(bytes[60..64].try_into()?) as usize;
    let header = bytes
        .get(offset..offset.saturating_add(6))
        .context("Invalid PE header")?;
    ensure!(&header[..4] == b"PE\0\0", "Invalid PE signature");
    let expected_machine = if cfg!(target_arch = "x86_64") {
        0x8664
    } else if cfg!(target_arch = "aarch64") {
        0xaa64
    } else {
        0x014c
    };
    ensure!(
        u16::from_le_bytes(header[4..6].try_into()?) == expected_machine,
        "Incompatible update architecture"
    );
    Ok(())
}

pub fn download(
    update: &AvailableUpdate,
    path: &Path,
    mut progress: impl FnMut(u32),
) -> Result<String> {
    validate_url(&update.binary, &update.version)?;
    let hash = if let Some(hash) = &update.expected_sha256 {
        hash.clone()
    } else {
        let checksum = update.checksum.as_ref().context("Missing checksum")?;
        validate_url(checksum, &update.version)?;
        let mut response = agent(20).get(&checksum.browser_download_url).call()?;
        let text = response
            .body_mut()
            .with_config()
            .limit(4096)
            .read_to_string()?;
        parse_checksum(&text, &update.binary.name)?
    };
    let mut created = false;
    let result = (|| -> Result<()> {
        let mut response = agent(180).get(&update.binary.browser_download_url).call()?;
        let mut reader = response
            .body_mut()
            .with_config()
            .limit(MAX_DOWNLOAD + 1)
            .reader();
        let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
        created = true;
        let mut total = 0u64;
        let mut previous = 101;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total += count as u64;
            ensure!(
                total <= update.binary.size && total <= MAX_DOWNLOAD,
                "Update exceeded its declared size"
            );
            file.write_all(&buffer[..count])?;
            let percent = (total * 100 / update.binary.size) as u32;
            if percent != previous {
                progress(percent);
                previous = percent;
            }
        }
        ensure!(total == update.binary.size, "Incomplete update download");
        file.sync_all()?;
        drop(file);
        let bytes = crate::storage::read_bounded(path, MAX_DOWNLOAD)?;
        verify_binary(&bytes, &hash)?;
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(path);
    }
    result?;
    Ok(hash)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPlan {
    pub target: PathBuf,
    pub staged: PathBuf,
    pub backup: PathBuf,
    pub helper: PathBuf,
    pub sha256: String,
    pub parent_pid: u32,
    pub parent_creation: u64,
}

/// Transaction core is separately testable with synthetic files and a fake launcher.
pub fn replace_and_launch(
    plan: &InstallPlan,
    launch: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let bytes = crate::storage::read_bounded(&plan.staged, MAX_DOWNLOAD)?;
    verify_binary(&bytes, &plan.sha256)?;
    ensure!(!plan.backup.exists(), "Recovery copy already exists");
    fs::rename(&plan.target, &plan.backup).context("Cannot preserve the installed executable")?;
    if let Err(error) = fs::rename(&plan.staged, &plan.target) {
        fs::rename(&plan.backup, &plan.target)
            .context("Restore failed; recovery copy is preserved")?;
        return Err(error.into());
    }
    if let Err(error) = launch(&plan.target) {
        fs::rename(&plan.target, &plan.staged)?;
        fs::rename(&plan.backup, &plan.target)
            .context("Restore failed; recovery copy is preserved")?;
        return Err(error);
    }
    Ok(())
}

#[cfg(windows)]
pub fn prepare_install(update: &AvailableUpdate, progress: impl FnMut(u32)) -> Result<PathBuf> {
    use std::os::windows::process::CommandExt;
    let target = std::env::current_exe()?.canonicalize()?;
    let parent = target.parent().context("Missing application directory")?;
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_micros()
    );
    let staged = parent.join(format!(".SleepDiagnostics-{nonce}-staged.exe"));
    let helper = parent.join(format!(".SleepDiagnostics-{nonce}-helper.exe"));
    let backup = parent.join(format!(".SleepDiagnostics-{nonce}-previous.exe"));
    let manifest = parent.join(format!(".SleepDiagnostics-{nonce}-plan.json"));
    let hash = download(update, &staged, progress)?;
    let result = (|| -> Result<()> {
        fs::copy(&target, &helper)?;
        let plan = InstallPlan {
            target,
            staged: staged.clone(),
            backup,
            helper: helper.clone(),
            sha256: hash,
            parent_pid: std::process::id(),
            parent_creation: current_creation()?,
        };
        crate::storage::atomic_write(&manifest, &serde_json::to_vec(&plan)?)?;
        std::process::Command::new(&helper)
            .arg("--apply-update")
            .arg(&manifest)
            .creation_flags(0x08000000)
            .spawn()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(staged);
        let _ = fs::remove_file(helper);
        let _ = fs::remove_file(&manifest);
    }
    result?;
    Ok(manifest)
}

#[cfg(windows)]
fn current_creation() -> Result<u64> {
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: A pseudo-handle valid for the lifetime of the current process.
    creation_time(unsafe { GetCurrentProcess() })
}
#[cfg(windows)]
fn creation_time(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<u64> {
    use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
    let mut created = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: Valid process handle and four writable FILETIME outputs.
    let succeeded =
        unsafe { GetProcessTimes(handle, &mut created, &mut exit, &mut kernel, &mut user) };
    ensure!(succeeded != 0, "Cannot verify updater process identity");
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

#[cfg(windows)]
pub fn apply_install(manifest: &Path) -> Result<()> {
    use std::os::windows::{fs::MetadataExt, process::CommandExt};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0},
        System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            WaitForSingleObject,
        },
    };
    let plan: InstallPlan =
        serde_json::from_slice(&crate::storage::read_bounded(manifest, 16384)?)?;
    let helper = std::env::current_exe()?.canonicalize()?;
    ensure!(
        helper == plan.helper.canonicalize()?,
        "Updater helper does not match its plan"
    );
    let directory = helper.parent().context("Missing updater directory")?;
    for path in [
        &plan.target,
        &plan.staged,
        &plan.backup,
        &plan.helper,
        manifest,
    ] {
        ensure!(
            path.parent()
                .context("Invalid update path")?
                .canonicalize()?
                == directory,
            "Update path escapes application directory"
        );
        if path.exists() {
            ensure!(
                fs::symlink_metadata(path)?.file_attributes() & 0x400 == 0,
                "Update paths cannot be reparse points"
            );
        }
    }
    for (path, suffix) in [
        (plan.staged.as_path(), "-staged.exe"),
        (plan.backup.as_path(), "-previous.exe"),
        (plan.helper.as_path(), "-helper.exe"),
        (manifest, "-plan.json"),
    ] {
        let name = path
            .file_name()
            .context("Invalid update filename")?
            .to_string_lossy();
        ensure!(
            name.starts_with(".SleepDiagnostics-") && name.ends_with(suffix),
            "Invalid update filename"
        );
    }
    ensure!(
        plan.target != plan.staged && plan.target != helper && valid_hash(&plan.sha256),
        "Invalid update plan"
    );
    // SAFETY: Read-only process identity/synchronization handle; no elevation or process termination.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            plan.parent_pid,
        )
    };
    if !process.is_null() {
        let result = (|| -> Result<()> {
            ensure!(
                creation_time(process)? == plan.parent_creation,
                "Parent PID was reused"
            );
            // SAFETY: Waits on the verified process, bounded to one minute.
            let wait = unsafe { WaitForSingleObject(process, 60_000) };
            ensure!(
                wait == WAIT_OBJECT_0,
                "Application has not closed; update was not installed"
            );
            Ok(())
        })();
        // SAFETY: Closes the owned process handle exactly once.
        unsafe {
            CloseHandle(process);
        }
        result?;
    } else {
        // SAFETY: Immediately follows failed OpenProcess.
        let code = unsafe { GetLastError() };
        ensure!(
            code == ERROR_INVALID_PARAMETER,
            "Cannot verify parent process exit"
        );
    }
    replace_and_launch(&plan, |target| {
        std::process::Command::new(target)
            .arg("--updated")
            .arg(manifest)
            .creation_flags(0x08000000)
            .spawn()?;
        Ok(())
    })?;
    Ok(())
}

pub fn exported_hash(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let len = file.read(&mut buffer)?;
        if len == 0 {
            break;
        }
        hash.update(&buffer[..len]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn cleanup_completed_install(manifest: &Path, current: &Path) -> Result<()> {
    let plan: InstallPlan =
        serde_json::from_slice(&crate::storage::read_bounded(manifest, 16384)?)?;
    let current = current.canonicalize()?;
    ensure!(
        plan.target.canonicalize()? == current,
        "Cleanup is only valid in the updated application"
    );
    let directory = current.parent().context("Missing application directory")?;
    let helper_name = plan
        .helper
        .file_name()
        .context("Missing helper filename")?
        .to_str()
        .context("Invalid helper filename")?;
    let prefix = helper_name
        .strip_suffix("-helper.exe")
        .context("Invalid helper filename")?;
    ensure!(
        prefix.starts_with(".SleepDiagnostics-"),
        "Invalid helper prefix"
    );
    for (path, suffix) in [
        (&plan.helper, "-helper.exe"),
        (&plan.backup, "-previous.exe"),
        (&manifest.to_path_buf(), "-plan.json"),
    ] {
        ensure!(
            path.parent()
                .context("Invalid cleanup path")?
                .canonicalize()?
                == directory
                && path
                    .file_name()
                    .is_some_and(|name| name == format!("{prefix}{suffix}").as_str()),
            "Cleanup path escapes its update transaction"
        );
    }
    verify_binary(
        &crate::storage::read_bounded(&current, MAX_DOWNLOAD)?,
        &plan.sha256,
    )?;
    for _ in 0..20 {
        match fs::remove_file(&plan.helper) {
            Ok(()) => {
                fs::remove_file(manifest)?;
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::remove_file(manifest)?;
                return Ok(());
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    anyhow::bail!("Helper cleanup was deferred; the recovery executable was preserved")
}
