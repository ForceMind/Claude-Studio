import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, mkdtemp, open, readFile, readdir, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { extractFile, listPackage } from '@electron/asar';
import { NtExecutable, NtExecutableResource, Resource } from 'resedit';
import { installedMarker } from './shell/windows-edition.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const sevenZip = path.join(root, 'node_modules', 'electron-winstaller', 'vendor', '7z-x64.exe');

function archive(args) {
  return execFileSync(sevenZip, args, { cwd: root, encoding: 'utf8', windowsHide: true });
}

export async function sha256(file, options) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file, options)) hash.update(chunk);
  return hash.digest('hex');
}

async function peInfo(file) {
  const input = await open(file);
  try {
    const header = Buffer.alloc(64);
    await input.read(header, 0, header.length, 0);
    assert.equal(header.toString('ascii', 0, 2), 'MZ');
    const pe = Buffer.alloc(24);
    await input.read(pe, 0, pe.length, header.readUInt32LE(60));
    assert.equal(pe.readUInt32LE(0), 0x4550);
    const machine = pe.readUInt16LE(4);
    const count = pe.readUInt16LE(6);
    const sections = Buffer.alloc(count * 40);
    const offset = header.readUInt32LE(60) + pe.length + pe.readUInt16LE(20);
    await input.read(sections, 0, sections.length, offset);
    for (let i = 0; i < sections.length; i += 40) {
      if (sections.toString('ascii', i, i + 5) !== '.text') continue;
      const start = sections.readUInt32LE(i + 20);
      return { machine, code: { start, end: start + sections.readUInt32LE(i + 16) - 1 } };
    }
    throw new Error('No PE code section: ' + file);
  } finally {
    await input.close();
  }
}

function frameHash(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function icoFrameHashes(ico) {
  assert.equal(ico.readUInt16LE(2), 1, 'Windows ICO');
  const count = ico.readUInt16LE(4);
  assert.ok(count >= 6, 'icon supports common Windows DPI sizes');
  return Array.from({ length: count }, (_, index) => {
    const item = 6 + index * 16;
    const length = ico.readUInt32LE(item + 8);
    const offset = ico.readUInt32LE(item + 12);
    return frameHash(ico.subarray(offset, offset + length));
  }).sort();
}

async function verifyIcon(exe, expected) {
  // This parser only reads PE resources. The release build separately checks Authenticode.
  const pe = NtExecutable.from(await readFile(exe), { ignoreCert: true });
  const entries = NtExecutableResource.from(pe).entries;
  const firstGroup = entries.filter(entry => entry.type === 14).sort((a, b) => Number(a.id) - Number(b.id))[0];
  assert.ok(firstGroup, 'default PE icon group in ' + exe);
  const group = Buffer.from(firstGroup.bin);
  const frames = new Map(entries.filter(entry => entry.type === 3 && entry.lang === firstGroup.lang)
    .map(entry => [entry.id, entry.bin]));
  const actual = Array.from({ length: group.readUInt16LE(4) }, (_, index) => {
    const id = group.readUInt16LE(6 + index * 14 + 12);
    const frame = frames.get(id);
    assert.ok(frame, 'embedded icon frame ' + id);
    return frameHash(Buffer.from(frame));
  }).sort();
  assert.deepEqual(actual, expected, 'default icon is the application artwork in ' + exe);
  return entries;
}

export async function verifyPackage(exe, { installer = false, verifierHash } = {}) {
  const expectedIcon = icoFrameHashes(await readFile(path.join(root, 'browser', 'assets', 'icon.ico')));
  const outerResources = await verifyIcon(exe, expectedIcon);
  const outerEditions = Resource.VersionInfo.fromEntries(outerResources).flatMap(item =>
    item.getAllLanguagesForStringValues().map(language => item.getStringValues(language).ClaudeUpdateEdition));
  assert.ok(outerEditions.length && outerEditions.every(edition => edition === (installer ? 'setup' : undefined)),
    'outer PE declares the expected update edition');
  assert.ok([0x014c, 0x8664].includes((await peInfo(exe)).machine), 'Windows launcher PE signature');
  const tempRoot = path.join(root, '.build-temp');
  await mkdir(tempRoot, { recursive: true });
  const scratch = await mkdtemp(path.join(tempRoot, 'verify-package-'));
  try {
    const listing = archive(['l', '-slt', exe]);
    assert.match(listing, /Type = Nsis/i, 'NSIS archive');
    const nestedArchive = listing.split(/\r?\n/).map(line => line.match(/^Path = (.+\.7z)$/i)?.[1])
      .find(name => name && /(?:^|[\\/])app-64\.7z$/i.test(name));
    assert.ok(nestedArchive, 'x64 app payload in Windows EXE');
    archive(['e', '-y', '-bsp0', '-o' + scratch, exe, nestedArchive]);
    const payload = path.join(scratch, 'app-64.7z');
    const unpacked = path.join(scratch, 'app');
    archive(['x', '-y', '-bsp0', '-o' + unpacked, payload]);
    const engine = path.join(unpacked, 'ClaudeBrowser.exe');
    const upstream = path.join(root, 'node_modules', 'electron', 'dist', 'electron.exe');
    await verifyIcon(engine, expectedIcon);
    const bundledPE = await peInfo(engine);
    const officialPE = await peInfo(upstream);
    assert.equal(bundledPE.machine, 0x8664, 'embedded Chromium launcher is x64');
    assert.equal(await sha256(engine, bundledPE.code), await sha256(upstream, officialPE.code),
      'embedded executable code matches Electron, including after ASAR integrity metadata is added');
    for (const member of ['icudtl.dat', 'resources.pak', 'chrome_100_percent.pak', 'v8_context_snapshot.bin',
      'ffmpeg.dll', 'd3dcompiler_47.dll', 'locales/en-US.pak', 'locales/zh-CN.pak', 'resources/app.asar']) {
      assert.ok((await stat(path.join(unpacked, member))).size > 0, member);
    }

    const marker = await readFile(path.join(unpacked, 'resources', installedMarker), 'utf8').catch(error => {
      if (error.code === 'ENOENT') return;
      throw error;
    });
    assert.equal(marker, installer ? 'installed\n' : undefined, 'only the installer payload has the installed edition marker');
    const asar = path.join(unpacked, 'resources', 'app.asar');
    const entries = listPackage(asar).map(entry => entry.replace(/\\/g, '/').replace(/^\//, ''));
    const packageData = JSON.parse(extractFile(asar, 'package.json').toString('utf8'));
    const expected = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
    assert.equal(packageData.version, expected.version);
    assert.equal(packageData.main, 'dist-app/main.cjs');
    const resources = ['index.html', 'profile-empty.html', 'main.cjs', 'preload.cjs', 'renderer.js', 'renderer.css', 'icon.png'];
    const packagedVerifier = 'dist-app/windows-authenticode.exe';
    assert.ok(!entries.some(member => /(?:^|\/)update-preview-/.test(member)), 'no preview fixtures in the Windows browser package');
    assert.equal(entries.includes(packagedVerifier), Boolean(verifierHash), 'only the signed build ships an install helper');
    if (verifierHash) resources.push('windows-authenticode.exe');
    for (const member of resources) {
      const bundled = 'dist-app/' + member;
      assert.ok(entries.includes(bundled), bundled);
      assert.deepEqual(extractFile(asar, bundled), await readFile(path.join(root, bundled)), bundled);
    }
    const main = extractFile(asar, packageData.main).toString('utf8');
    if (verifierHash) {
      assert.equal(createHash('sha256').update(extractFile(asar, packagedVerifier)).digest('hex'), verifierHash);
      assert.ok(main.includes(verifierHash), 'packaged entry binds the signed helper bytes');
    }
    assert.match(main, /createProductionUpdates/);
    assert.match(main, /account-clear/);
    assert.match(main, /account-remove/);
    assert.match(main, /setAppDetails/);
    assert.match(main, /ClosedPages/);
    const html = extractFile(asar, 'dist-app/index.html').toString('utf8');
    const renderer = extractFile(asar, 'dist-app/renderer.js').toString('utf8');
    assert.match(renderer, /account-environment/);
    assert.match(renderer, /check-exit/);
    assert.match(renderer, /mail-picker/);
    assert.match(renderer, /claude-link-dialog/);
    assert.match(main, /persist:mailbox-/);
    assert.match(main, /transferableClaudeURL/);
    assert.match(main, /chooseClaudeLink/);
    assert.match(main, /executeJavaScriptInIsolatedWorld/);
    assert.match(main, /api64\.ipify\.org/);
    assert.match(main, /shell:detect-proxy/);
    assert.match(main, /mail\.google\.com/);
    assert.match(renderer, /proxy-port/);
    assert.match(main, /create-account/);
    assert.match(renderer, /add-account/);
    assert.match(renderer, /tab-rail/);
    assert.match(renderer, /America\/Los_Angeles/);
    assert.match(extractFile(asar, 'dist-app/preload.cjs').toString('utf8'), /shell:detect-proxy/);
    for (const marker of ['WebContentsView', 'setWindowOpenHandler', 'createWindow(options)', 'persist:account-',
      'loadFile(html)', 'preload.cjs', 'preparePopup(guest, space,', 'adoptLinkedTab', 'foreground-tab',
      'outlivesOpener: true', 'Emulation.setTimezoneOverride',
      'Emulation.setUserAgentOverride', 'proxyBypassRules', 'PORTABLE_EXECUTABLE_DIR']) {
      assert.ok(main.includes(marker), 'real app entry contains ' + marker);
    }
    assert.match(html, /src="[.]/);
    assert.match(html, /renderer\.css/);
    assert.match(html, /rel="icon" href="\.\/icon\.png"/);
    console.log('已核对外层 EXE、内嵌 EXE 的默认图标和窗口 PNG 资源。');
    assert.doesNotMatch(main, /launchPersistentContext|playwright-core|msedge|BrowserPanel/);
    assert.doesNotMatch(entries.join('\n'), /(?:^|\/)(?:\.browser-local|playwright-core|BrowserPanel|settings\.json)(?:\/|\.|$)/m);
    assert.ok((await readdir(path.join(unpacked, 'locales'))).length > 1);

    const size = (await stat(exe)).size;
    const hash = await sha256(exe);
    console.log('已解包验证 Windows x64 Electron ' + expected.devDependencies.electron + ' · ' + packageData.version +
      ' · ' + size + ' bytes · SHA-256 ' + hash);
    return hash;
  } finally {
    assert.equal(path.dirname(path.resolve(scratch)), path.resolve(tempRoot));
    await rm(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const installer = process.argv.includes('--installer');
  const input = process.argv.slice(2).find(arg => arg !== '--installer');
  const fallback = installer ? 'release/windows/installer/ClaudeBrowser-Setup.exe' : 'ClaudeBrowser.exe';
  await verifyPackage(input ? path.resolve(input) : path.join(root, fallback), { installer });
}
