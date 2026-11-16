const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');

const TAG = 'v0.1.0';
const NAME = 'SleepDiagnostics-v0.1.0.exe';
const BODY = [
  'Initial release of Sleep Diagnostics, a read-only Windows sleep and wake evidence explorer.',
  '',
  '## Added',
  '- A native Windows timeline with concise explanations, confidence levels and supporting power events.',
  '- Bounded collection of relevant System events, current power requests, wake-source/timer reports and device capabilities. Collection is manual and does not request that Windows stay awake.',
  '- Conservative correlation across sleep, resume, reboot, Modern Standby and clock-change boundaries. Current requests and devices allowed to wake are not presented as proof of a past cause.',
  '- Offline XML/JSON imports, bounded local history, configurable retention, clear history and redacted report export.',
  '- English, Russian, French, German, Spanish and Italian catalogs; persistent light/dark themes and reduced motion.',
  '- Startup/manual update checks with an opt-out and user-initiated SHA-256-verified installation with recovery and restart.',
  '',
  '## Downloads',
  '- Windows x64; requires Windows 10 or later. The application requests normal user permissions.',
  '- `SleepDiagnostics-v0.1.0.exe`: portable application.',
  '- `SleepDiagnostics-v0.1.0.exe.sha256`: SHA-256 integrity check for the executable.',
  '- `SleepDiagnostics-v0.1.0-portable.zip`: executable, checksum, MIT license and dependency license notices.',
  '',
  '## Verification and limitations',
  '- Verified with 42 synthetic-data Rust regression tests, formatting, strict Clippy, release compilation and static PE/icon/manifest checks. Release publication is also tested with fake GitHub responses.',
  '- GUI interaction, live Windows collection, idle/hidden performance and actual update installation have not been exercised in the code-only session.',
  '- A wake source is not always recorded. Unrecognized localized powercfg reports are marked unavailable rather than guessed.',
  '- This app does not change power plans, scheduled tasks, wake permissions, services or registry settings.',
].join('\n');

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

async function publish({ github, context, core, root = process.cwd() }) {
  if (context.repo.owner !== 'siarheisinelnikau' || context.repo.repo !== 'sleep-diagnostics' || context.eventName !== 'push' || context.ref !== 'refs/heads/main' || context.payload?.head_commit?.message !== `release: publish ${TAG}` || !/^[0-9a-f]{40}$/.test(context.sha)) {
    throw new Error('Release publication requires the explicit release commit on the canonical main branch.');
  }
  const manifest = await fs.readFile(path.join(root, 'Cargo.toml'), 'utf8');
  if (!/\[package\][\s\S]*?\nversion = "0\.1\.0"\r?\n/.test(manifest)) throw new Error('Release version does not match Cargo.toml.');
  const artifacts = [];
  for (const name of [NAME, `${NAME}.sha256`, `SleepDiagnostics-${TAG}-portable.zip`]) {
    const data = await fs.readFile(path.join(root, 'dist', name));
    if (data.length === 0) throw new Error(`Empty release asset: ${name}`);
    artifacts.push({ name, data });
  }
  const checksum = artifacts[1].data.toString('utf8').trim().split(/\s+/);
  if (checksum.length !== 2 || checksum[1] !== NAME || checksum[0] !== sha256(artifacts[0].data)) throw new Error('Executable checksum mismatch.');
  if (artifacts[0].data.subarray(0, 2).toString() !== 'MZ' || artifacts[2].data.subarray(0, 2).toString() !== 'PK') throw new Error('Invalid executable or archive.');
  const repo = context.repo;
  let existing;
  try { existing = (await github.rest.repos.getReleaseByTag({ ...repo, tag: TAG })).data; }
  catch (error) { if (error.status !== 404) throw error; }
  if (existing) throw new Error('This release already exists; published releases are never overwritten.');
  const draft = (await github.rest.repos.createRelease({ ...repo, tag_name: TAG, target_commitish: context.sha, name: `Sleep Diagnostics ${TAG}`, body: BODY, draft: true, prerelease: false })).data;
  for (const asset of artifacts) {
    const uploaded = (await github.rest.repos.uploadReleaseAsset({ ...repo, release_id: draft.id, name: asset.name, data: asset.data, headers: { 'content-type': asset.name.endsWith('.zip') ? 'application/zip' : 'application/octet-stream', 'content-length': asset.data.length } })).data;
    if (uploaded.state !== 'uploaded' || uploaded.size !== asset.data.length || uploaded.digest && uploaded.digest !== `sha256:${sha256(asset.data)}`) throw new Error(`GitHub asset verification failed: ${asset.name}`);
  }
  const release = (await github.rest.repos.updateRelease({ ...repo, release_id: draft.id, draft: false, make_latest: 'true' })).data;
  core.notice(`Published ${release.html_url}`);
  return release;
}

module.exports = { publish, TAG, BODY, NAME };
