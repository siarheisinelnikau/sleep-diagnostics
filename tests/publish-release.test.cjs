const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { publish, NAME } = require('../scripts/publish-release.cjs');

async function setup(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'sleep-release-'));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('sleep-release-'));
    return fs.rm(root, { recursive: true, force: true });
  });
  await fs.mkdir(path.join(root, 'dist'));
  const exe = Buffer.from('MZ synthetic release bytes');
  const hash = createHash('sha256').update(exe).digest('hex');
  await fs.writeFile(path.join(root, 'Cargo.toml'), '[package]\nversion = "0.1.0"\n');
  await fs.writeFile(path.join(root, 'dist', NAME), exe);
  await fs.writeFile(path.join(root, 'dist', `${NAME}.sha256`), `${options.badHash ? '0'.repeat(64) : hash}  ${NAME}\n`);
  await fs.writeFile(path.join(root, 'dist', 'SleepDiagnostics-v0.1.0-portable.zip'), 'PK synthetic license archive');
  const calls = [];
  const github = { rest: { repos: {
    getReleaseByTag: async () => { calls.push('lookup'); if (options.existing) return { data: { id: 99 } }; throw Object.assign(new Error('Missing'), { status: 404 }); },
    createRelease: async data => { calls.push('draft'); assert.equal(data.draft, true); return { data: { id: 1 } }; },
    uploadReleaseAsset: async asset => { calls.push(asset.name); if (options.uploadFailure) throw new Error('Synthetic upload failure'); return { data: { state: 'uploaded', size: options.badSize ? 0 : asset.data.length, digest: `sha256:${createHash('sha256').update(asset.data).digest('hex')}` } }; },
    updateRelease: async data => { calls.push('publish'); assert.equal(data.draft, false); return { data: { html_url: 'https://example.invalid/release' } }; },
  } } };
  return { root, github, calls, context: { repo: { owner: 'siarheisinelnikau', repo: 'sleep-diagnostics' }, eventName: 'push', ref: 'refs/heads/main', sha: 'a'.repeat(40), payload: { head_commit: { message: 'release: publish v0.1.0' } } }, core: { notice() {} } };
}

test('uploads every verified asset before publishing', async t => {
  const run = await setup(t); await publish(run);
  assert.deepEqual(run.calls, ['lookup', 'draft', NAME, `${NAME}.sha256`, 'SleepDiagnostics-v0.1.0-portable.zip', 'publish']);
});
test('checksum failure creates no remote release', async t => {
  const run = await setup(t, { badHash: true }); await assert.rejects(publish(run), /checksum/); assert.deepEqual(run.calls, []);
});
test('a normal source push cannot publish a release', async t => {
  const run = await setup(t); run.context.payload.head_commit.message = 'fix: update code'; await assert.rejects(publish(run), /explicit release/); assert.deepEqual(run.calls, []);
});
test('past releases cannot be overwritten', async t => {
  const run = await setup(t, { existing: true }); await assert.rejects(publish(run), /already exists/); assert.deepEqual(run.calls, ['lookup']);
});
test('failed upload leaves the release unpublished', async t => {
  const run = await setup(t, { uploadFailure: true }); await assert.rejects(publish(run), /upload failure/); assert.ok(!run.calls.includes('publish'));
});
test('asset verification failure leaves the release unpublished', async t => {
  const run = await setup(t, { badSize: true }); await assert.rejects(publish(run), /verification failed/); assert.ok(!run.calls.includes('publish'));
});
