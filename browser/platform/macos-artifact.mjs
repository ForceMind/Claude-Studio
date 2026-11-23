import path from 'node:path';

const bundleId = 'com.claudestudio.browser';
const teamIdPattern = /^[A-Z0-9]{10}$/;
const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const unavailableCode = 'MAC_OFFLINE_TRUST_UNAVAILABLE';

function checkedPolicy({ teamId, arch, version } = {}) {
  if (typeof teamId !== 'string' || !teamIdPattern.test(teamId)) {
    throw new Error('macOS 更新必须明确指定 10 位 Team ID。');
  }
  if (arch !== 'arm64' && arch !== 'x64') {
    throw new Error('macOS 更新必须明确指定当前 arm64 或 x64 架构。');
  }
  if (typeof version !== 'string' || version.length > 128 || !versionPattern.test(version)) {
    throw new Error('macOS 更新必须明确指定精确的完整候选版本号。');
  }
  return { teamId, arch, version };
}

/** Query before offering any Mac asset download or installation action. */
export function getMacArtifactVerificationAvailability() {
  return Object.freeze({
    available: false,
    installable: false,
    code: unavailableCode,
    hostSupported: process.platform === 'darwin',
    reason: '尚无已验证的 macOS 原生离线代码签名与公证票据验证器；禁止下载后安装。'
  });
}

/**
 * Identity comparison only, for synthetic fixtures and a future native boundary.
 * These fields are assertions, not cryptographic evidence. Even all matching
 * fields (including a claimed ticket) never produce an installable result.
 */
export function checkMacArtifactMetadata(metadata, policy) {
  const expected = checkedPolicy(policy);
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)
      || metadata.platform !== 'darwin' || metadata.bundleId !== bundleId
      || metadata.teamId !== expected.teamId || metadata.arch !== expected.arch
      || metadata.version !== expected.version
      || metadata.signerType !== 'Developer ID Application'
      || metadata.hardenedRuntime !== true || metadata.adHoc !== false) {
    throw new Error('macOS 包的 Bundle ID、Team ID、架构、精确版本或正式签名元数据不符合策略。');
  }
  return Object.freeze({
    metadataMatched: true,
    signatureVerified: false,
    notarizationVerified: false,
    installable: false,
    bundleId,
    ...expected
  });
}

/**
 * Fail-closed production boundary; intentionally no archive parser or extractor.
 * The caller has already checked the manifest's Ed25519 signature and ZIP hash.
 * That authenticates the download, but cannot replace Apple's platform trust.
 *
 * Apple documents stapler's CloudKit access in:
 * https://developer.apple.com/documentation/security/customizing-the-notarization-workflow
 * `stapler validate` can compare with the current online ticket, so it is NOT an
 * offline verifier. Do not invoke stapler, spctl, notarytool, launch the app, or
 * change quarantine as a fallback here.
 *
 * Security.framework exposes kSecCSNoNetworkAccess for static code validation,
 * but this project has no verified native binding/helper, nor proof of a local
 * ticket validation path. Static identity metadata, an embedded ticket's mere
 * presence, or a cached Gatekeeper result are insufficient to turn this on.
 *
 * Consequently ZIP bytes are not opened, decompressed, or written anywhere:
 * zip-slip, symlink traversal and decompression bombs never reach extraction.
 * Enabling this requires a reviewed bounded archive implementation preserving
 * legitimate Electron framework symlinks, immutable staging/hash checks, native
 * offline signature validation (Apple anchor, Developer ID, expected Team and
 * Bundle ID, all nested code), verified local ticket binding, and Mac evidence
 * for arm64/x64, altered packages, missing tickets and cancellation/cleanup.
 */
export async function verifyMacArtifact(file, { teamId, arch, version, signal } = {}) {
  signal?.throwIfAborted();
  checkedPolicy({ teamId, arch, version });
  if (typeof file !== 'string' || !path.isAbsolute(file)
      || path.extname(file).toLowerCase() !== '.zip' || /[\r\n\0]/.test(file)) {
    throw new Error('macOS 更新包需要绝对 ZIP 文件路径。');
  }
  if (process.platform === 'darwin' && arch !== process.arch) {
    throw new Error('macOS 更新候选架构与当前应用架构不一致；禁止安装。');
  }
  const availability = getMacArtifactVerificationAvailability();
  const error = new Error(availability.reason);
  error.code = unavailableCode;
  error.installable = false;
  error.availability = availability;
  throw error;
}
