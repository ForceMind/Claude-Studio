import { createPublicKey } from 'node:crypto';
import { isIP } from 'node:net';
import { isNewerVersion } from './release-manifest.mjs';

const supportedTargets = new Set(['win32-x64', 'darwin-arm64', 'darwin-x64']);
const product = 'com.claudestudio.browser';
const maxAssetBytes = 400 * 1024 * 1024;
const pin = /^[a-f0-9]{64}$/;

export const releaseFuses = Object.freeze({
  runAsNode: false,
  enableNodeOptionsEnvironmentVariable: false,
  enableNodeCliInspectArguments: false,
  enableEmbeddedAsarIntegrityValidation: true,
  onlyLoadAppFromAsar: true
});

function httpsURL(input) {
  if (typeof input !== 'string') throw new Error('更新地址必须是 HTTPS URL。');
  const url = new URL(input);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hash || url.search ||
      !host.includes('.') || host.endsWith('.') || isIP(host) || /\.(localhost|local|internal)$/.test(host) ||
      /%(?:2f|5c|25)/i.test(url.pathname)) {
    throw new Error('更新地址不符合 HTTPS 发布策略。');
  }
  return url;
}

export function normalizeDesktopPolicy(input) {
  if (input?.schema !== 1 || input.channel !== 'stable' || input.product !== product ||
      typeof input.publicKey !== 'string' || !/^-----BEGIN PUBLIC KEY-----[\s\S]+-----END PUBLIC KEY-----\s*$/.test(input.publicKey)) {
    throw new Error('生产更新策略的版本、产品、渠道或公钥无效。');
  }
  const key = createPublicKey(input.publicKey);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('生产更新公钥必须使用 Ed25519。');
  if (!input.targets || typeof input.targets !== 'object' || Array.isArray(input.targets)) {
    throw new Error('生产更新策略缺少目标平台。');
  }
  const targets = {};
  for (const [id, target] of Object.entries(input.targets)) {
    if (!supportedTargets.has(id) || !target || !Number.isSafeInteger(target.minSequence) || target.minSequence < 1) {
      throw new Error('生产更新平台或最低序号无效。');
    }
    const feed = httpsURL(target.feed);
    if (!feed.pathname.endsWith('.json') || !Array.isArray(target.assets) ||
        target.assets.length < 1 || target.assets.length > 8) throw new Error('必须明确指定清单和安装包的 HTTPS 路径。');
    const assets = target.assets.map(entry => {
      const base = httpsURL(entry);
      if (!base.pathname.endsWith('/')) throw new Error('安装包路径前缀须以 / 结束。');
      return base.href;
    });
    if (id.startsWith('win32-')) {
      if (!Array.isArray(target.signerPins) || !target.signerPins.length || target.signerPins.length > 16 ||
          target.signerPins.some(value => typeof value !== 'string' || !pin.test(value))) {
        throw new Error('Windows 发布证书须配置 SHA-256 指纹。');
      }
      targets[id] = { feed: feed.href, assets, minSequence: target.minSequence, signerPins: [...new Set(target.signerPins)] };
    } else {
      if (typeof target.teamId !== 'string' || !/^[A-Z0-9]{10}$/.test(target.teamId)) {
        throw new Error('macOS 发布者须配置 Team ID。');
      }
      targets[id] = { feed: feed.href, assets, minSequence: target.minSequence, teamId: target.teamId };
    }
  }
  if (!Object.keys(targets).length) throw new Error('生产更新策略缺少目标平台。');
  return { schema: 1, product, channel: 'stable', publicKey: key.export({ type: 'spki', format: 'pem' }), targets };
}

export function desktopTarget(input, platform, arch, installedVersion) {
  const policy = normalizeDesktopPolicy(input);
  isNewerVersion(installedVersion, installedVersion); // Require a stable numeric application version.
  const target = policy.targets[platform + '-' + arch];
  if (!target) throw new Error('当前架构没有生产更新策略。');
  const extension = platform === 'win32' ? '.exe' : '.zip';
  return {
    ...target, publicKey: policy.publicKey, channel: policy.channel, product: policy.product, platform, arch,
    extension, maxAssetBytes, installedVersion, allowCurrent: true,
    allowAssetURL(url) {
      try {
        const canonical = httpsURL(url.href);
        return canonical.pathname.toLowerCase().endsWith(extension) &&
          target.assets.some(base => canonical.href.startsWith(base));
      } catch { return false; }
    }
  };
}
