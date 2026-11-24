import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const certificatePin = /^[a-fA-F0-9]{64}$/;
const product = 'Claude Browser';
const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function windowsOnly() {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    throw new Error('Windows 生产更新验签需要 Windows x64；不可用时禁止安装。');
  }
}

function absoluteFile(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || /[\r\n\0]/.test(value)) {
    throw new Error(`${label}需要绝对文件路径。`);
  }
  return path.normalize(value);
}

/** Build-time only. Ship this EXE in trusted application resources, never in the feed. */
export async function compileWindowsVerifier(output, { installPins = [], version = '0.0.0' } = {}) {
  windowsOnly();
  if (!Array.isArray(installPins) || installPins.length > 16
      || installPins.some(pin => typeof pin !== 'string' || !certificatePin.test(pin))) {
    throw new Error('安装器只接受构建时明确配置的 SHA-256 签名证书指纹。');
  }
  if (typeof version !== 'string' || !/^(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})$/.test(version) ||
      version.split('.').some(part => Number(part) > 65535)) {
    throw new Error('Windows 安装助手需要有效的三段数字发布版本。');
  }
  const destination = absoluteFile(output, '验签器输出');
  if (path.extname(destination).toLowerCase() !== '.exe') throw new Error('验签器输出必须为 EXE。');
  const compiler = path.join(process.env.SystemRoot || 'C:\\Windows',
    'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
  await mkdir(path.dirname(destination), { recursive: true });
  const scratch = await mkdtemp(path.join(path.dirname(destination), '.authenticode-build-'));
  const temporary = path.join(scratch, 'windows-authenticode.exe');
  try {
    const source = await readFile(new URL('./windows-authenticode.cs', import.meta.url), 'utf8');
    const marker = 'private const string EmbeddedInstallPins = ""; // BUILD_INSTALL_PINS';
    if (source.split(marker).length !== 2) throw new Error('安装器证书编译标记不唯一。');
    const baked = [...new Set(installPins.map(pin => pin.toLowerCase()))].join(',');
    const compiledSource = path.join(scratch, 'windows-authenticode.cs');
    await writeFile(compiledSource, source.replace(marker, `private const string EmbeddedInstallPins = "${baked}";`));
    const metadata = path.join(scratch, 'assembly-info.cs');
    await writeFile(metadata, 'using System.Reflection;\n' +
      `[assembly: AssemblyProduct("${product}")]\n` +
      `[assembly: AssemblyFileVersion("${version}.0")]\n` +
      `[assembly: AssemblyInformationalVersion("${version}")]\n`);
    await execute(compiler, ['/nologo', '/target:exe', '/platform:x64', '/optimize+',
      '/r:System.Web.Extensions.dll', `/out:${temporary}`,
      metadata, compiledSource, fileURLToPath(new URL('./windows-install.cs', import.meta.url))],
    { windowsHide: true, timeout: 30_000, maxBuffer: 64 * 1024 });
    await rename(temporary, destination);
    return destination;
  } catch (cause) {
    throw new Error('无法构建 Windows 离线验签器；禁止以其他验签方式降级。', { cause });
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

/**
 * The caller first verifies the Ed25519 manifest and its asset hash, and compares
 * this result.sha256 again. Keep staging private and recheck before replacement.
 * verifierPath must point to the bundled verifier in trusted app resources.
 * Only the outer PE architecture is checked here (NSIS can use an i386 stub).
 * The x64 payload requires release-time unpack validation plus the signed
 * manifest's platform/arch/hash contract; outerMachine is not that evidence.
 */
export async function verifyWindowsArtifact(file, { verifierPath, signerPins, version, signal, edition } = {}) {
  windowsOnly();
  const candidate = absoluteFile(file, '更新文件');
  const verifier = absoluteFile(verifierPath, '随应用附带的验签器');
  if (!Array.isArray(signerPins) || signerPins.length < 1 || signerPins.length > 16
      || signerPins.some(pin => typeof pin !== 'string' || !certificatePin.test(pin))) {
    throw new Error('必须明确配置 SHA-256 签名证书指纹（64 位十六进制）；不接受 SHA-1 或发布者名称。');
  }
  const pins = [...new Set(signerPins.map(pin => pin.toLowerCase()))];
  if (typeof version !== 'string' || version.length > 128 || !versionPattern.test(version)) {
    throw new Error('更新目标需要精确的完整版本号。');
  }
  if (edition !== undefined && !['setup', 'portable', 'application'].includes(edition)) {
    throw new Error('Windows 更新包版型无效。');
  }
  const args = [candidate, version, pins.join(',')];
  if (edition) args.push(edition);
  let output;
  try {
    output = await execute(verifier, args, {
      windowsHide: true, timeout: 30_000, maxBuffer: 64 * 1024, signal
    });
  } catch (cause) {
    if (cause.code === 'ABORT_ERR' || signal?.aborted) throw cause;
    let failure;
    try { failure = JSON.parse(cause.stdout); } catch { /* unavailable / malformed fails closed */ }
    const code = typeof failure?.code === 'string' && /^[A-Z_]{1,64}$/.test(failure.code)
      ? failure.code : 'VERIFIER_UNAVAILABLE';
    const error = new Error(`Windows 更新包离线验证失败（${code}）；禁止安装。`, { cause });
    error.code = code;
    if (/^0x[0-9A-F]{8}$/.test(failure?.trustStatus)) error.trustStatus = failure.trustStatus;
    throw error;
  }
  let result;
  try { result = JSON.parse(output.stdout); } catch {
    throw new Error('Windows 验签器返回无效结果；禁止安装。');
  }
  if (result?.schema !== 1 || result.ok !== true || result.offline !== true
      || result.platform !== 'win32' || !['i386', 'amd64'].includes(result.outerMachine)
      || result.architectureScope !== 'outer-pe-only' || result.product !== product
      || result.version !== version || result.trustStatus !== '0x00000000'
      || typeof result.signerSha256 !== 'string' || !certificatePin.test(result.signerSha256)
      || !pins.includes(result.signerSha256.toLowerCase())
      || typeof result.sha256 !== 'string' || !certificatePin.test(result.sha256)) {
    throw new Error('Windows 验签结果与证书、产品、版本或架构策略不一致；禁止安装。');
  }
  return Object.freeze({ ...result, signerSha256: result.signerSha256.toLowerCase(), sha256: result.sha256.toLowerCase() });
}
