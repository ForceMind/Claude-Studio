import { createHash, createPublicKey, sign, verify } from 'node:crypto';

const checksum = /^[a-f0-9]{64}$/;
const versionPattern = /^(0|[1-9]\d{0,6})\.(0|[1-9]\d{0,6})\.(0|[1-9]\d{0,6})$/;

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function versionParts(version) {
  const match = typeof version === 'string' && versionPattern.exec(version);
  if (!match) throw new Error('版本号格式无效。');
  return match.slice(1).map(Number);
}

export function isNewerVersion(candidate, current) {
  const next = versionParts(candidate);
  const installed = versionParts(current);
  const different = next.findIndex((part, index) => part !== installed[index]);
  return different >= 0 && next[different] > installed[different];
}

function parseObject(json) {
  const result = JSON.parse(json);
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('清单格式无效。');
  return result;
}

export function signReleaseManifest(manifest, privateKey) {
  const payload = JSON.stringify(manifest);
  return JSON.stringify({ payload, signature: sign(null, Buffer.from(payload), privateKey).toString('base64') });
}

export function checkReleaseManifest(envelope, policy) {
  if (Buffer.byteLength(envelope) > 16_384) throw new Error('清单超过大小限制。');
  const { payload, signature } = parseObject(envelope);
  if (typeof payload !== 'string' || typeof signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(signature)) {
    throw new Error('清单签名格式无效。');
  }
  const key = createPublicKey(policy.publicKey);
  if (key.asymmetricKeyType !== 'ed25519' ||
      !verify(null, Buffer.from(payload), key, Buffer.from(signature, 'base64'))) {
    throw new Error('清单签名无效。');
  }
  const manifest = parseObject(payload);
  if (manifest.schema !== 1 || manifest.product !== policy.product || manifest.channel !== policy.channel ||
      manifest.platform !== policy.platform || manifest.arch !== policy.arch) {
    throw new Error('清单产品、渠道或目标平台不匹配。');
  }
  if (!Number.isSafeInteger(manifest.expiresAt) || manifest.expiresAt <= (policy.now ?? Date.now())) {
    throw new Error('清单已过期。');
  }
  if (!Number.isSafeInteger(manifest.sequence) || manifest.sequence < 1 ||
      manifest.sequence < (policy.minSequence ?? 1) ||
      manifest.sequence < (policy.previous?.sequence ?? 0) ||
      (manifest.sequence === policy.previous?.sequence && sha256(payload) !== policy.previous.digest)) {
    throw new Error('清单序号回退或同序号内容发生变化。');
  }
  if (typeof manifest.sha256 !== 'string' || !checksum.test(manifest.sha256) ||
      !Number.isSafeInteger(manifest.size) || manifest.size < 1 || manifest.size > policy.maxAssetBytes) {
    throw new Error('包哈希或大小无效。');
  }
  const available = isNewerVersion(manifest.version, policy.installedVersion);
  if (!available && !(policy.allowCurrent && manifest.version === policy.installedVersion)) {
    throw new Error('候选版本低于适用的版本下限。');
  }
  if (policy.previous?.version && isNewerVersion(policy.previous.version, manifest.version)) {
    throw new Error('候选版本低于此前已接受的版本。');
  }
  if (typeof manifest.url !== 'string') throw new Error('包地址无效。');
  const asset = new URL(manifest.url);
  if (asset.username || asset.password || asset.hash || !policy.allowAssetURL(asset)) {
    throw new Error('包地址不在当前渠道允许的范围。');
  }
  return { version: manifest.version, size: manifest.size, sha256: manifest.sha256, url: asset.href, available,
    expiresAt: manifest.expiresAt,
    state: { sequence: manifest.sequence, digest: sha256(payload), version: manifest.version } };
}
