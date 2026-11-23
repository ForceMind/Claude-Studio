import { createPublicKey, verify } from 'node:crypto';
import { get } from 'node:http';
import { InvalidManifest } from './update-check.ts';

const maxManifestBytes = 16_384;
const previewVersion = /^(0|[1-9]\d{0,6})\.(0|[1-9]\d{0,6})\.(0|[1-9]\d{0,6})-update-preview\.([1-9]\d{0,6})$/;

function versionParts(version: unknown): number[] {
  const match = typeof version === 'string' && previewVersion.exec(version);
  if (!match) throw new InvalidManifest('Invalid update preview version');
  return match.slice(1).map(Number);
}

function jsonObject(value: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(value);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
  } catch {
    throw new InvalidManifest('Invalid JSON');
  }
  throw new InvalidManifest('Expected a JSON object');
}

export function checkPreviewManifest(
  envelope: string, publicKey: string, currentVersion: string, now = Date.now()
): string | undefined {
  if (Buffer.byteLength(envelope) > maxManifestBytes) throw new InvalidManifest('Manifest exceeds the preview limit');
  const { payload, signature } = jsonObject(envelope);
  if (typeof payload !== 'string' || typeof signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(signature)) {
    throw new InvalidManifest('Invalid signature envelope');
  }
  const key = createPublicKey(publicKey);
  if (key.asymmetricKeyType !== 'ed25519' || !verify(null, Buffer.from(payload), key, Buffer.from(signature, 'base64'))) {
    throw new InvalidManifest('Manifest signature mismatch');
  }
  const manifest = jsonObject(payload);
  if (manifest.schema !== 1 || manifest.channel !== 'update-preview' || manifest.platform !== 'win32' ||
      manifest.arch !== 'x64' || typeof manifest.expiresAt !== 'number' ||
      !Number.isSafeInteger(manifest.expiresAt) || manifest.expiresAt <= now) {
    throw new InvalidManifest('Manifest target or expiration is invalid');
  }
  const candidate = versionParts(manifest.version);
  const current = versionParts(currentVersion);
  const different = candidate.findIndex((part, index) => part !== current[index]);
  return different !== -1 && candidate[different] > current[different] ? manifest.version as string : undefined;
}

export function previewEndpoint(value: string): URL {
  const endpoint = new URL(value);
  if (endpoint.protocol !== 'http:' || endpoint.hostname !== '127.0.0.1' || !endpoint.port ||
      endpoint.pathname !== '/manifest.json' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error('The test feed must be http://127.0.0.1:PORT/manifest.json.');
  }
  return endpoint;
}

export function readPreviewFeed(endpoint: URL, signal: AbortSignal): Promise<string> {
  const url = previewEndpoint(endpoint.href);
  return new Promise((resolve, reject) => {
    const request = get(url, { agent: false, signal: AbortSignal.any([signal, AbortSignal.timeout(5000)]) }, response => {
      response.on('error', reject);
      if (response.statusCode !== 200) {
        reject(new Error('The test feed returned HTTP ' + response.statusCode));
        response.destroy();
        return;
      }
      const chunks: Buffer[] = [];
      let length = 0;
      response.on('data', (chunk: Buffer) => {
        length += chunk.length;
        if (length > maxManifestBytes) {
          reject(new InvalidManifest('Manifest exceeds the preview limit'));
          response.destroy();
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    request.on('error', reject);
  });
}
