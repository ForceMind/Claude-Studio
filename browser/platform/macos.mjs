import { execFile } from 'node:child_process';
import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { releaseFuses } from '../update/desktop-policy.mjs';

const run = promisify(execFile);
const developerIdPrefix = 'Developer ID Application: ';
const modes = new Set(['local', 'signed', 'notarized']);
const supportedArchitectures = new Set(['arm64', 'x64']);
const outputFormat = ['dmg', 'zip'];
const artifactName = 'ClaudeBrowser-${version}-mac-${arch}.${ext}';

function signingIdentity(value) {
  if (typeof value !== 'string' || !value.startsWith(developerIdPrefix)
      || !/^.+ \([A-Z0-9]{10}\)$/.test(value.slice(developerIdPrefix.length))
      || /[\r\n\0]/.test(value)) {
    throw new Error('正式 macOS 构建需要完整的 Developer ID Application: 名称 (TEAMID)，通过 identity 或 MAC_SIGNING_IDENTITY 指定。');
  }
  return value.trim();
}

function assertNotarizationCredentials(env) {
  // Match electron-builder 26.18's credential precedence. A partial earlier
  // group must fail even if a later group is complete. Never copy secrets into
  // build configuration, logs, or generated manifests.
  const groups = [
    ['APPLE_ID', 'APPLE_APP_SPECIFIC_PASSWORD', 'APPLE_TEAM_ID'],
    ['APPLE_API_KEY', 'APPLE_API_KEY_ID', 'APPLE_API_ISSUER'],
    ['APPLE_KEYCHAIN_PROFILE']
  ];
  for (const names of groups) {
    const triggers = names[0] === 'APPLE_ID' ? names.slice(0, 2) : names;
    if (!triggers.some(name => env[name])) continue;
    if (!names.every(name => typeof env[name] === 'string' && env[name].trim())) {
      throw new Error(`macOS 公证凭据不完整，需要环境变量：${names.join(', ')}。`);
    }
    return;
  }
  throw new Error('macOS 公证需要明确配置 Apple ID、App Store Connect API key 或 Keychain profile 凭据。');
}

/** Pure configuration: safe to inspect and test on Windows without Apple tools. */
export function createMacBuildPlan({ projectDir, mode = 'local', architectures = ['arm64', 'x64'], identity, env = process.env } = {}) {
  if (typeof projectDir !== 'string' || !projectDir.trim()) throw new Error('macOS 构建需要 projectDir。');
  if (!modes.has(mode)) throw new Error('macOS mode 必须为 local、signed 或 notarized。');
  if (!Array.isArray(architectures) || architectures.length === 0
      || architectures.some(arch => !supportedArchitectures.has(arch))
      || new Set(architectures).size !== architectures.length) {
    throw new Error('macOS 架构仅支持不重复的 arm64、x64 独立包。');
  }
  const formal = mode !== 'local';
  const certificate = formal ? signingIdentity(identity ?? env.MAC_SIGNING_IDENTITY) : undefined;
  if (mode === 'notarized') assertNotarizationCredentials(env);
  return {
    mode,
    architectures: [...architectures],
    identity: certificate,
    config: {
      appId: 'com.claudestudio.browser',
      productName: 'Claude Browser',
      directories: { output: `release/macos/${mode}` },
      // The Windows baseline points at the locally installed Windows Electron.
      // Resolve/download the correct Darwin Electron for each target instead.
      electronDist: null,
      npmRebuild: false,
      files: ['dist-app/**/*', 'package.json', 'LICENSE', '!**/.browser-local/**'],
      asar: true,
      forceCodeSigning: formal,
      publish: null,
      mac: {
        target: outputFormat.map(target => ({ target, arch: [...architectures] })),
        artifactName,
        icon: 'browser/assets/icon.png',
        type: 'distribution',
        // v26 rejects a certificate type prefix in its identity qualifier.
        // Distribution mode restricts selection to Developer ID Application.
        identity: formal ? certificate.slice(developerIdPrefix.length) : '-',
        hardenedRuntime: formal,
        notarize: mode === 'notarized',
        // Keep the osx-sign default Electron entitlements (including JIT).
        // Custom camera/microphone/plugin entitlements require separate review.
        gatekeeperAssess: false
      },
      dmg: { sign: formal }
    },
    verification: {
      codeSignature: formal,
      hardenedRuntime: formal,
      developerId: formal,
      stapledTicket: mode === 'notarized',
      gatekeeper: mode === 'notarized',
      runtimeAndProfileMigration: 'requires-arm64-and-x64-mac-validation'
    }
  };
}

/** Validate actual codesign metadata, separately from process exit status. */
export function assertMacSigningDetails(details, expectedIdentity) {
  const certificate = signingIdentity(expectedIdentity);
  const team = /\(([A-Z0-9]{10})\)$/.exec(certificate)[1];
  const lines = details.split(/\r?\n/);
  if (!lines.includes(`Authority=${certificate}`) || !lines.includes(`TeamIdentifier=${team}`)) {
    throw new Error('macOS 签名身份或 TeamIdentifier 与明确指定的 Developer ID 不一致。');
  }
  if (!lines.some(line => /^CodeDirectory\b.*flags=.*\bruntime\b/.test(line))) {
    throw new Error('macOS 正式签名未启用 Hardened Runtime。');
  }
}

export async function getMacBuildArtifacts(projectDir, plan, builtFiles) {
  const { version } = JSON.parse(await readFile(path.join(projectDir, 'package.json'), 'utf8'));
  const output = path.resolve(projectDir, plan.config.directories.output);
  const emitted = new Set(builtFiles.map(file => path.resolve(projectDir, file)));
  const verifiedFiles = [];
  for (const arch of plan.architectures) {
    for (const ext of outputFormat) {
      const name = artifactName.replace('${version}', version).replace('${arch}', arch).replace('${ext}', ext);
      const file = path.join(output, name);
      if (!emitted.has(file)) throw new Error(`macOS 本次构建未输出 ${name}。`);
      const details = await lstat(file);
      if (!details.isFile() || details.size === 0) throw new Error(`macOS 构建产物无效：${name}。`);
      verifiedFiles.push(file);
    }
  }
  return verifiedFiles;
}

/** Never publishes. Notarization can upload to Apple only in explicit mode. */
export async function buildMacPackages(options = {}) {
  // Fail before loading electron-builder or creating directories on Windows.
  if (process.platform !== 'darwin') throw new Error('macOS DMG/ZIP 打包、签名和公证必须在 macOS 构建机执行。');
  const plan = createMacBuildPlan({ ...options, env: process.env });
  if (options.production && plan.mode !== 'notarized') throw new Error('生产更新包需要显式公证模式。');
  const { Arch, Platform, build } = await import('electron-builder');
  const config = { ...plan.config };
  if (options.production) config.electronFuses = releaseFuses;
  const verifiedArchitectures = new Set();
  if (plan.mode !== 'local') {
    config.afterSign = async context => {
      const appPath = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`);
      await run('codesign', ['--verify', '--deep', '--strict', '--verbose=2', appPath]);
      const details = await run('codesign', ['--display', '--verbose=4', appPath]);
      assertMacSigningDetails(`${details.stdout}\n${details.stderr}`, plan.identity);
      if (plan.mode === 'notarized') {
        // In builder 26.18 afterSign runs after notarize/staple and before ZIP.
        await run('xcrun', ['stapler', 'validate', appPath]);
        await run('spctl', ['--assess', '--verbose=2', '--type', 'exec', appPath]);
      }
      verifiedArchitectures.add(context.arch);
    };
  }
  const artifacts = await build({
    projectDir: path.resolve(options.projectDir),
    config,
    targets: Platform.MAC.createTarget(outputFormat, ...plan.architectures.map(arch => Arch[arch])),
    publish: 'never'
  });
  // Some CI/PR conditions bypass signing before forceCodeSigning is checked.
  // Never report a formal build as successful when afterSign was skipped.
  if (plan.mode !== 'local'
      && plan.architectures.some(arch => !verifiedArchitectures.has(Arch[arch]))) {
    throw new Error('macOS 正式构建有架构未完成签名/公证验证；禁止发布本批产物。');
  }
  const verifiedFiles = await getMacBuildArtifacts(options.projectDir, plan, artifacts);
  for (const file of verifiedFiles) {
    if (path.extname(file) === '.dmg') {
      await run('/usr/bin/hdiutil', ['verify', file]);
      if (plan.mode !== 'local') await run('/usr/bin/codesign', ['--verify', '--verbose=2', file]);
    } else {
      await run('/usr/bin/unzip', ['-tq', file]);
    }
  }
  return verifiedFiles;
}
