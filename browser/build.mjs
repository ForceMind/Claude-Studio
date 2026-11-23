import { build } from 'esbuild';
import { copyFile, mkdir, readFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { desktopTarget, normalizeDesktopPolicy, releaseFuses } from './update/desktop-policy.mjs';
import { sha256 } from './update/release-manifest.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const out = path.join(root, 'dist-app');
const entry = name => path.join(root, 'browser', 'shell', name);
const packaging = process.argv.includes('--package');
const mac = process.platform === 'darwin' || process.argv.includes('--mac');
const macArchOptions = process.argv.filter(argument => argument === '--mac-arch' || argument.startsWith('--mac-arch='));
const macArchitectures = macArchOptions.length ? [macArchOptions[0].slice('--mac-arch='.length)] : ['arm64', 'x64'];
if (macArchOptions.length && (!packaging || !mac || macArchOptions.length !== 1 || !['arm64', 'x64'].includes(macArchitectures[0]))) {
  throw new Error('macOS 打包只接受一个 --mac-arch=arm64 或 --mac-arch=x64。');
}
const macMode = process.argv.includes('--mac-notarize') ? 'notarized' :
  process.argv.includes('--mac-signed') ? 'signed' : 'local';
const policyArgument = process.argv.find(argument => argument.startsWith('--release-policy='));
if (packaging && mac && process.platform !== 'darwin') {
  throw new Error('macOS 包需要在 macOS 主机上构建。');
}
if (packaging && !mac && (process.platform !== 'win32' || process.arch !== 'x64')) {
  throw new Error('本项目的 Windows 发布包需要 Windows x64 构建环境。');
}
const verifierFile = path.join(out, 'windows-authenticode.exe');
let release = null;
let windowsTarget;
if (policyArgument) {
  if (!packaging) throw new Error('生产更新策略只用于签名打包。');
  const config = normalizeDesktopPolicy(JSON.parse(await readFile(policyArgument.slice('--release-policy='.length), 'utf8')));
  const { version } = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  if (mac) {
    if (macMode !== 'notarized') throw new Error('使用生产更新策略的 macOS 包需要显式公证模式。');
    for (const arch of macArchitectures) {
      const target = desktopTarget(config, 'darwin', arch, version);
      if (!process.env.MAC_SIGNING_IDENTITY?.endsWith(' (' + target.teamId + ')')) {
        throw new Error('macOS 更新策略的 Team ID 与明确指定的发布签名不一致。');
      }
    }
  } else {
    windowsTarget = desktopTarget(config, 'win32', 'x64', version);
  }
  release = { config };
}

await mkdir(out, { recursive: true });
await Promise.all(['update-preview-preload.cjs', 'update-preview.html', 'update-preview.js', 'update-preview-fixture.json']
  .map(name => rm(path.join(out, name), { force: true })));
if (windowsTarget) {
  const { compileWindowsVerifier } = await import('./platform/windows-artifact.mjs');
  await compileWindowsVerifier(verifierFile, { installPins: windowsTarget.signerPins });
} else {
  await rm(verifierFile, { force: true });
}

const electron = { bundle: true, platform: 'node', format: 'cjs', external: ['electron'], target: 'node22' };
const bundleMain = () => build({ ...electron, entryPoints: [entry('main.ts')], outfile: path.join(out, 'main.cjs'),
  define: { __DESKTOP_RELEASE__: JSON.stringify(release) } });
await Promise.all([
  ...(windowsTarget ? [] : [bundleMain()]),
  build({ ...electron, entryPoints: [entry('preload.ts')], outfile: path.join(out, 'preload.cjs') }),
  build({
    bundle: true, platform: 'browser', target: 'chrome135', jsx: 'automatic',
    define: { 'process.env.NODE_ENV': '"production"' },
    entryPoints: [entry('renderer.tsx')], outfile: path.join(out, 'renderer.js'),
    minify: true, legalComments: 'inline'
  }),
  ...['index.html', 'profile-empty.html'].map(name => copyFile(entry(name), path.join(out, name))),
  copyFile(path.join(root, 'browser', 'assets', 'icon.png'), path.join(out, 'icon.png'))
]);

if (packaging && mac) {
  const { buildMacPackages } = await import('./platform/macos.mjs');
  await buildMacPackages({ projectDir: root, mode: macMode, architectures: macArchitectures, identity: process.env.MAC_SIGNING_IDENTITY,
    production: Boolean(release) });
} else if (packaging) {
  const tempRoot = path.join(root, '.build-temp');
  await mkdir(tempRoot, { recursive: true });
  process.env.TEMP = tempRoot;
  process.env.TMP = tempRoot;
  process.env.ELECTRON_BUILDER_CACHE ??= path.join(root, '.electron-builder-cache');
  const { Arch, Platform, build: packageApp } = await import('electron-builder');
  await packageApp({ projectDir: root, targets: Platform.WINDOWS.createTarget(['portable'], Arch.x64), publish: 'never',
    ...(release ? { config: {
      directories: { output: 'release/windows/stable' }, forceCodeSigning: true, electronFuses: releaseFuses,
      win: { signExecutable: true },
      async beforePack({ packager }) {
        if (!await packager.signIf(verifierFile)) throw new Error('正式包需要先签名 Windows 安装助手。');
        release.verifierHash = sha256(await readFile(verifierFile));
        await bundleMain();
      }
    } } : {}) });

  const artifact = path.join(root, release ? 'release/windows/stable/ClaudeBrowser.exe' : 'release/ClaudeBrowser.exe');
  const { verifyPackage, sha256: hashFile } = await import('./verify-package.mjs');
  const hash = await verifyPackage(artifact, { verifierHash: release?.verifierHash });
  if (release) {
    if (!release.verifierHash) throw new Error('正式包缺少签名安装助手。');
    const { verifyWindowsArtifact } = await import('./platform/windows-artifact.mjs');
    const result = await verifyWindowsArtifact(artifact, { verifierPath: verifierFile,
      signerPins: windowsTarget.signerPins, version: windowsTarget.installedVersion });
    if (result.sha256 !== hash) throw new Error('签名验证的包与已解包验证的文件不同。');
    console.log('已生成签名发布候选包：' + artifact);
  } else {
    const launcher = path.join(root, 'ClaudeBrowser.exe');
    const backup = path.join(root, 'release', 'previous-launcher.exe');
    const pending = path.join(tempRoot, 'launcher-' + randomUUID() + '.tmp');
    const current = await hashFile(launcher).catch(error => {
      if (error.code !== 'ENOENT') throw error;
    });
    if (current && current !== hash) {
      const { constants } = await import('node:fs');
      await copyFile(launcher, backup, constants.COPYFILE_EXCL).catch(error => {
        if (error.code !== 'EEXIST') throw error;
      });
    }
    try {
      await copyFile(artifact, pending);
      if (await hashFile(pending) !== hash) throw new Error('复制后的 EXE 校验失败。');
      await rename(pending, launcher);
    } finally {
      await rm(pending, { force: true });
    }
    console.log('入口已更新：' + launcher);
    const { updateLocalLauncher } = await import('./local-install.mjs');
    const installed = await updateLocalLauncher(artifact, hash);
    if (installed) console.log('本机已更新：' + installed);
  }
}
