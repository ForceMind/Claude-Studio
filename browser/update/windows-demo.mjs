import { execFile } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, open, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { createServer, get } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { stdin, stdout } from 'node:process';
import { createInterface } from 'node:readline/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { checkReleaseManifest, sha256, signReleaseManifest } from './release-manifest.mjs';

const execute = promisify(execFile);
const targetName = 'ClaudeBrowser-UpdateDemo.exe';
const privateDirPrefix = 'claude-update-demo-';
const demoSource = version => 'using System; class Demo {' +
  'static void Main(string[] args) { Console.WriteLine("' + version + '");' +
  'if (args.Length == 1 && args[0] == "--hold") Console.ReadLine(); } }';

export async function createDemo() {
  if (process.platform !== 'win32') throw new Error('此演练需要 Windows 和本机 .NET Framework 编译器。');
  const parent = await realpath(tmpdir());
  const root = await mkdtemp(path.join(parent, privateDirPrefix));
  const target = path.join(root, targetName);
  const next = path.join(root, 'sample-next.exe');
  const helper = path.join(root, 'portable-demo-helper.exe');
  const data = path.join(root, 'sample-profile.json');
  const compiler = path.join(process.env.SystemRoot || 'C:\\Windows',
    'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
  const temporarySource = path.join(root, 'sample.cs');
  const compile = (source, destination) => execute(compiler, ['/nologo', '/target:exe', '/out:' + destination, source]);
  const clean = async () => {
    const resolved = await realpath(root);
    if (path.dirname(resolved) !== parent || !path.basename(resolved).startsWith(privateDirPrefix)) {
      throw new Error('演练目录已变化。');
    }
    await rm(resolved, { recursive: true, force: true });
  };
  try {
    await writeFile(temporarySource, demoSource('1.0.0'));
    await compile(temporarySource, target);
    await writeFile(temporarySource, demoSource('1.0.1'));
    await compile(temporarySource, next);
    await compile(fileURLToPath(new URL('./portable-demo-helper.cs', import.meta.url)), helper);
    await writeFile(data, JSON.stringify({ accountA: 'synthetic-a', accountB: 'synthetic-b' }));
    const previousHash = sha256(await readFile(target));
    const bytes = await readFile(next);
    return { root, target, helper, data, previousHash, bytes, clean };
  } catch (error) {
    await clean();
    throw error;
  }
}

export async function startDemoFeed(bytes) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const key = publicKey.export({ type: 'spki', format: 'pem' });
  let content = bytes;
  let requests = 0;
  let manifest;
  const server = createServer((request, response) => {
    if (request.url === '/manifest.json') response.end(manifest);
    else if (request.url === '/sample.exe') {
      requests += 1;
      response.end(content);
    } else response.writeHead(404).end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = 'http://127.0.0.1:' + server.address().port;
  const details = { schema: 1, product: 'com.claudestudio.browser.update-demo', channel: 'synthetic',
    platform: 'win32', arch: 'x64', version: '1.0.1', sequence: 1,
    expiresAt: Date.now() + 600_000, size: bytes.length, sha256: sha256(bytes), url: origin + '/sample.exe' };
  manifest = signReleaseManifest(details, privateKey);
  const policy = { publicKey: key, product: details.product, channel: details.channel,
    platform: details.platform, arch: details.arch, installedVersion: '1.0.0', maxAssetBytes: 1_048_576,
    allowAssetURL: url => url.origin === origin && url.pathname === '/sample.exe' && !url.search };
  return {
    manifestURL: origin + '/manifest.json', policy,
    sign: overrides => signReleaseManifest({ ...details, ...overrides }, privateKey),
    assetRequests: () => requests,
    replaceContent: next => { content = next; },
    close: () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
  };
}

function readLoopback(url, limit) {
  const target = new URL(url);
  if (target.protocol !== 'http:' || target.hostname !== '127.0.0.1' || !target.port ||
      target.username || target.password || target.hash) throw new Error('演练只允许本机回环地址。');
  return new Promise((resolve, reject) => {
    const request = get(target, { agent: false, signal: AbortSignal.timeout(10_000) }, response => {
      response.on('error', reject);
      if (response.statusCode !== 200) {
        reject(new Error('演练服务响应失败。'));
        response.destroy();
        return;
      }
      let size = 0;
      const chunks = [];
      response.on('data', chunk => {
        size += chunk.length;
        if (size > limit) {
          reject(new Error('响应超过签名清单允许的大小。'));
          response.destroy();
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve(Buffer.concat(chunks)));
    });
    request.on('error', reject);
  });
}

export function applyDemoUpdate(demo, asset, processId = 0) {
  return execute(demo.helper, [demo.root, demo.previousHash, asset.sha256, String(processId)], { timeout: 20_000 });
}

export async function runDemoUpdate(demo, feed, confirm) {
  const envelope = await readLoopback(feed.manifestURL, 16_384);
  const asset = checkReleaseManifest(envelope.toString('utf8'), feed.policy);
  if (!await confirm('download', asset)) return 'download-declined';
  const bytes = await readLoopback(asset.url, asset.size);
  if (bytes.byteLength !== asset.size || sha256(bytes) !== asset.sha256) {
    throw new Error('下载文件大小或哈希与签名清单不符。');
  }
  const staged = path.join(demo.root, 'candidate.pending');
  const file = await open(staged, 'wx');
  try {
    try {
      await file.writeFile(bytes);
      await file.sync();
    }
    finally { await file.close(); }
    if (!await confirm('install', asset)) return 'install-declined';
    await applyDemoUpdate(demo, asset);
    return 'installed';
  } finally {
    await rm(staged, { force: true });
  }
}

export async function demoVersion(demo) {
  return (await execute(demo.target)).stdout.trim();
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const demo = await createDemo();
  let feed;
  const input = createInterface({ input: stdin, output: stdout });
  try {
    feed = await startDemoFeed(demo.bytes);
    console.log('当前合成版本 ' + await demoVersion(demo));
    const outcome = await runDemoUpdate(demo, feed, async (action, asset) => {
      const message = action === 'download' ? '发现签名清单中的版本 ' + asset.version + '。下载演练包' :
        '演练包已验证。确认替换合成程序';
      return (await input.question(message + '？[y/N] ')).trim().toLowerCase() === 'y';
    });
    console.log((outcome === 'installed' ? '已完成演练。' : '已取消演练。') + ' 当前合成版本 ' + await demoVersion(demo));
  } finally {
    input.close();
    try { await feed?.close(); }
    finally { await demo.clean(); }
  }
}
