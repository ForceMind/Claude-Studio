import { build } from 'esbuild';
import { copyFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { desktopTarget, normalizeDesktopPolicy, releaseFuses } from './update/desktop-policy.mjs';
import { sha256 } from './update/release-manifest.mjs';
import { installedMarker } from './shell/windows-edition.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const out = path.join(root, 'dist-app');
const entry = name => path.join(root, 'browser', 'shell', name);
const packaging = process.argv.includes('--package');
const installer = process.argv.includes('--installer');
const policyArgument = process.argv.find(argument => argument.startsWith('--release-policy='));
if (packaging && (process.platform !== 'win32' || process.arch !== 'x64')) {
  throw new Error('本项目的 Windows 发布包需要 Windows x64 构建环境。');
}
const verifierFile = path.join(out, 'windows-authenticode.exe');
let release = null;
let windowsTarget;
if (installer && !packaging) throw new Error('安装版目标需要打包。');
if (policyArgument) {
  if (!packaging) throw new Error('生产更新策略只用于签名打包。');
  const config = normalizeDesktopPolicy(JSON.parse(await readFile(policyArgument.slice('--release-policy='.length), 'utf8')));
  const { version } = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  windowsTarget = desktopTarget(config, 'win32', 'x64', version, installer ? 'setup' : undefined);
  release = { config };
}

await mkdir(out, { recursive: true });
if (windowsTarget) {
  const { compileWindowsVerifier } = await import('./platform/windows-artifact.mjs');
  await compileWindowsVerifier(verifierFile, {
    installPins: windowsTarget.signerPins, version: windowsTarget.installedVersion
  });
} else {
  await rm(verifierFile, { force: true });
}

const electron = { bundle: true, platform: 'node', format: 'cjs', external: ['electron'], target: 'node22' };
const bundleMain = () => build({ ...electron, entryPoints: [entry('main.ts')], outfile: path.join(out, 'main.cjs'),
  define: { __DESKTOP_RELEASE__: JSON.stringify(release) } });
await Promise.all([
  ...(release ? [] : [bundleMain()]),
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

if (packaging) {
  const tempRoot = path.join(root, '.build-temp');
  await mkdir(tempRoot, { recursive: true });
  process.env.TEMP = tempRoot;
  process.env.TMP = tempRoot;
  process.env.ELECTRON_BUILDER_CACHE ??= path.join(root, '.electron-builder-cache');
  const { Arch, Platform, build: packageApp } = await import('electron-builder');
  const installerMarkerFile = path.join(tempRoot, installedMarker);
  if (installer) await writeFile(installerMarkerFile, 'installed\n');
  const output = installer ? (release ? 'release/windows/stable/installer' : 'release/windows/installer') :
    (release ? 'release/windows/stable' : 'release');
  await packageApp({ projectDir: root, targets: Platform.WINDOWS.createTarget([installer ? 'nsis' : 'portable'], Arch.x64), publish: 'never',
    config: {
      directories: { output },
      ...(installer ? { extraResources: [{ from: installerMarkerFile, to: installedMarker }] } : {}),
      ...(release ? {
        forceCodeSigning: true, electronFuses: releaseFuses, win: { signExecutable: true },
        async beforePack({ packager }) {
          if (!await packager.signIf(verifierFile)) throw new Error('正式包需要先签名 Windows 安装助手。');
          release.verifierHash = sha256(await readFile(verifierFile));
          await bundleMain();
        }
      } : {})
    } });

  const artifact = path.join(root, output, installer ? 'ClaudeBrowser-Setup.exe' : 'ClaudeBrowser.exe');
  const { verifyPackage, sha256: hashFile } = await import('./verify-package.mjs');
  const hash = await verifyPackage(artifact, { installer, verifierHash: release?.verifierHash });
  if (release) {
    if (!release.verifierHash) throw new Error('正式包缺少签名安装助手。');
    const { verifyWindowsArtifact } = await import('./platform/windows-artifact.mjs');
    const result = await verifyWindowsArtifact(artifact, { verifierPath: verifierFile,
      signerPins: windowsTarget.signerPins, version: windowsTarget.installedVersion, edition: installer ? 'setup' : 'portable' });
    if (result.sha256 !== hash) throw new Error('签名验证的包与已解包验证的文件不同。');
    console.log('已生成签名发布候选包：' + artifact);
  } else if (installer) {
    console.log('安装包已通过校验：' + artifact);
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
