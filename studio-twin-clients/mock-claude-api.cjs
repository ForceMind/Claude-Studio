'use strict';
// High-fidelity local HTTPS TLS 1.2 Mock Claude Cloud API & OAuth PKCE Server.
// Listens ONLY on 127.0.0.1:<tlsPort>, never touches external internet or port 10810.
// Enforces:
//   - PKCE S256 code_verifier validation + single-use + expiry on /oauth/token
//   - Strict Bearer token <-> X-Account-Uuid <-> X-Org-Uuid binding (403 IDENTITY_MISMATCH on spoofing!)
//   - Real SSE chunked streaming on POST /v1/messages when stream=true (tests <3s fault cutoff!)
//   - Full NDJSON request audit log (records Accept-Language, X-Client, Account/Org UUID, path)

const https = require('https');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');

const port = parseInt(process.argv[2], 10);
const certPemPath = process.argv[3];
const keyPemPath = process.argv[4];
const logPath = process.argv[5];
const httpProbePort = parseInt(process.argv[6] || '0', 10);

if (!port || !certPemPath || !keyPemPath || !logPath) {
  console.error('Usage: node mock-claude-api.cjs <port> <certPem> <keyPem> <logPath>');
  process.exit(2);
}

const pendingCodes = new Map(); // code -> { state, codeChallenge, email, accountUuid, orgUuid, expiresAt, used }
const issuedTokens = new Map(); // token -> { email, accountUuid, orgUuid }

function appendLog(row) {
  try {
    fs.appendFileSync(logPath, JSON.stringify({ utc: new Date().toISOString(), ...row }) + '\n', 'utf8');
  } catch (_) {}
}

function sha256B64Url(s) {
  return crypto.createHash('sha256').update(s, 'ascii').digest('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (c) => { raw += c; if (raw.length > 65536) req.destroy(); });
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const buf = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': buf.length,
    'Connection': 'close'
  });
  res.end(buf);
}

const server = https.createServer({
  cert: fs.readFileSync(certPemPath),
  key: fs.readFileSync(keyPemPath),
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.2'
}, async (req, res) => {
  const path = (req.url || '/').split('?')[0];
  const acceptLang = req.headers['accept-language'] || '';
  const clientTag = req.headers['x-client'] || '';

  // Support StudioN3.Relay active upstream health probes (GET /n3/<16-hex-marker> -> "target:<marker>")
  if (req.method === 'GET') {
    const m = /^\/n3\/([a-f0-9]{16})$/.exec(path);
    if (m) {
      const b = Buffer.from('target:' + m[1], 'ascii');
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': b.length, 'Connection': 'close' });
      return res.end(b);
    }
    return sendJson(res, 404, { error: 'NOT_FOUND', path });
  }

  let body = {};
  try { body = await readJsonBody(req); } catch (_) {
    return sendJson(res, 400, { error: 'INVALID_JSON' });
  }

  // Host-side OAuth authorization issuer (simulates browser login consent returning an authorization code)
  if (req.method === 'POST' && path === '/oauth/issue-code') {
    const code = crypto.randomBytes(12).toString('hex');
    const ttlMs = typeof body.ttlMs === 'number' ? body.ttlMs : 120000;
    pendingCodes.set(code, {
      state: body.state || '',
      codeChallenge: body.code_challenge || '',
      email: body.email || 'lab@example.invalid',
      accountUuid: body.account_uuid || crypto.randomUUID(),
      orgUuid: body.org_uuid || crypto.randomUUID(),
      expiresAt: Date.now() + ttlMs,
      used: false
    });
    appendLog({ kind: 'oauth-issue', email: body.email, accountUuid: body.account_uuid, orgUuid: body.org_uuid, ttlMs });
    return sendJson(res, 200, { ok: true, code });
  }

  // OAuth PKCE code -> Bearer token exchange (called by ClaudeDesktopTwin / ClaudeCliTwin via proxy!)
  if (req.method === 'POST' && path === '/oauth/token') {
    const rec = pendingCodes.get(body.code || '');
    if (!rec) {
      appendLog({ kind: 'oauth-token-reject', reason: 'UNKNOWN_CODE', clientTag, acceptLang });
      return sendJson(res, 400, { error: 'UNKNOWN_CODE' });
    }
    if (rec.used) {
      appendLog({ kind: 'oauth-token-reject', reason: 'CODE_REPLAYED', clientTag, acceptLang });
      return sendJson(res, 400, { error: 'CODE_REPLAYED' });
    }
    if (Date.now() > rec.expiresAt) {
      appendLog({ kind: 'oauth-token-reject', reason: 'CODE_EXPIRED', clientTag, acceptLang });
      return sendJson(res, 400, { error: 'CODE_EXPIRED' });
    }
    if (rec.state !== (body.state || '')) {
      appendLog({ kind: 'oauth-token-reject', reason: 'STATE_MISMATCH', clientTag, acceptLang });
      return sendJson(res, 400, { error: 'STATE_MISMATCH' });
    }
    const derived = sha256B64Url(body.code_verifier || '');
    if (derived !== rec.codeChallenge) {
      appendLog({ kind: 'oauth-token-reject', reason: 'PKCE_VERIFIER_MISMATCH', clientTag, acceptLang });
      return sendJson(res, 400, { error: 'PKCE_VERIFIER_MISMATCH' });
    }
    rec.used = true;
    const token = 'sk-twin-' + crypto.randomBytes(18).toString('hex');
    issuedTokens.set(token, { email: rec.email, accountUuid: rec.accountUuid, orgUuid: rec.orgUuid });
    appendLog({ kind: 'oauth-token-ok', email: rec.email, accountUuid: rec.accountUuid, orgUuid: rec.orgUuid, clientTag, acceptLang });
    return sendJson(res, 200, {
      access_token: token,
      token_type: 'Bearer',
      email: rec.email,
      account_uuid: rec.accountUuid,
      org_uuid: rec.orgUuid
    });
  }

  if (req.method === 'POST' && path === '/v1/health') {
    appendLog({ kind: 'health', clientTag, acceptLang });
    return sendJson(res, 200, { ok: true, service: 'claude-twin-api', acceptLang });
  }

  if (req.method === 'POST' && path === '/v1/messages') {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    const sess = issuedTokens.get(token);
    if (!sess) {
      appendLog({ kind: 'messages-reject', reason: 'INVALID_TOKEN', clientTag, acceptLang });
      return sendJson(res, 401, { error: 'INVALID_TOKEN' });
    }
    const hdrAcct = req.headers['x-account-uuid'] || '';
    const hdrOrg = req.headers['x-org-uuid'] || '';
    if (hdrAcct !== sess.accountUuid || hdrOrg !== sess.orgUuid) {
      appendLog({ kind: 'messages-reject', reason: 'IDENTITY_MISMATCH', clientTag, hdrAcct, sessAcct: sess.accountUuid });
      return sendJson(res, 403, { error: 'IDENTITY_MISMATCH' });
    }

    const replyId = 'msg_' + crypto.randomBytes(6).toString('hex');
    appendLog({
      kind: body.stream ? 'messages-stream-start' : 'messages-ok',
      replyId,
      email: sess.email,
      accountUuid: sess.accountUuid,
      orgUuid: sess.orgUuid,
      clientTag,
      acceptLang,
      sessionId: body.session_id || ''
    });

    if (body.stream) {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
      });
      let seq = 0;
      const emit = () => {
        seq++;
        const ev = JSON.stringify({
          id: replyId,
          seq,
          accountUuid: sess.accountUuid,
          orgUuid: sess.orgUuid,
          acceptLang,
          delta: `chunk-${seq} for ${sess.email}`
        });
        try { res.write(`data: ${ev}\n\n`); } catch (_) {}
      };
      emit();
      const iv = setInterval(emit, 180);
      req.on('close', () => { clearInterval(iv); appendLog({ kind: 'messages-stream-closed', replyId, seq, email: sess.email }); });
      return;
    }

    return sendJson(res, 200, {
      id: replyId,
      type: 'message',
      model: body.model || 'claude-twin-sonnet',
      account_uuid: sess.accountUuid,
      org_uuid: sess.orgUuid,
      email: sess.email,
      accept_language_seen: acceptLang,
      client_seen: clientTag,
      content: [{
        type: 'text',
        text: `[Claude Twin Reply | ${sess.email} | ${acceptLang}] Received: ${String(body.prompt || '').slice(0, 120)}`
      }]
    });
  }

  return sendJson(res, 404, { error: 'NOT_FOUND', path });
});

let probeServer = null;
function startMain() {
  server.listen(port, '127.0.0.1', () => {
    process.stdout.write(JSON.stringify({ kind: 'ready', port, httpProbePort }) + '\n');
  });
}

if (httpProbePort > 0) {
  probeServer = http.createServer((req, res) => {
    const u = (req.url || '/');
    const m = /^\/n3\/([a-f0-9]{16})$/.exec(u);
    if (m) {
      const b = Buffer.from('target:' + m[1], 'ascii');
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': b.length, 'Connection': 'close' });
      return res.end(b);
    }
    const body = Buffer.from('ok\n', 'utf8');
    res.writeHead(u.startsWith('/studio-probe') ? 200 : 404, {
      'Content-Type': 'text/plain',
      'Content-Length': body.length,
      'Connection': 'close'
    });
    res.end(body);
  });
  probeServer.listen(httpProbePort, '127.0.0.1', startMain);
} else {
  startMain();
}
