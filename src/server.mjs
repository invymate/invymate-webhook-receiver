import crypto from 'node:crypto';
import http from 'node:http';

const DEFAULT_MAX_AGE_SECONDS = 300;
const DEFAULT_MAX_BODY_BYTES = 1_000_000;

function defaultLog(entry) {
  console.log(`[invymate-webhook][${entry.kind}] ${JSON.stringify(entry)}`);
}

function parseSignatureHeader(header) {
  return Object.fromEntries(
    String(header || '')
      .split(',')
      .filter((part) => part.includes('='))
      .map((part) => {
        const separator = part.indexOf('=');
        return [part.slice(0, separator).trim(), part.slice(separator + 1).trim()];
      }),
  );
}

export function verifyWebhookSignature(
  rawBody,
  signatureHeader,
  secret,
  now = Date.now(),
  maxAgeSeconds = DEFAULT_MAX_AGE_SECONDS,
) {
  if (!secret || !Buffer.isBuffer(rawBody)) return false;

  const { t: timestamp, v1: receivedSignature } = parseSignatureHeader(signatureHeader);
  const timestampNumber = Number(timestamp);
  if (!timestamp || !Number.isSafeInteger(timestampNumber) || !receivedSignature) return false;
  if (Math.abs(now / 1000 - timestampNumber) > maxAgeSeconds) return false;
  if (!/^[a-f0-9]{64}$/i.test(receivedSignature)) return false;

  const signedValue = Buffer.concat([Buffer.from(timestamp, 'ascii'), Buffer.from('.'), rawBody]);
  const expectedSignature = crypto.createHmac('sha256', secret).update(signedValue).digest('hex');
  const expectedBuffer = Buffer.from(expectedSignature, 'ascii');
  const receivedBuffer = Buffer.from(receivedSignature.toLowerCase(), 'ascii');
  return crypto.timingSafeEqual(expectedBuffer, receivedBuffer);
}

function readRequestBody(request, maxBodyBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBodyBytes) {
        const error = new Error(`Request body exceeds ${maxBodyBytes} bytes`);
        error.statusCode = 413;
        request.resume();
        reject(error);
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

function parseJson(rawBody) {
  try {
    return JSON.parse(rawBody.toString('utf8'));
  } catch {
    return null;
  }
}

function getHeader(request, name) {
  const value = request.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value || '';
}

function sendJson(response, status, payload, log) {
  const body = JSON.stringify(payload);
  const headers = {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  };
  response.writeHead(status, headers);
  response.end(body);
  log({ kind: 'response', status, headers, body });
}

export function createWebhookServer({
  secret,
  log = defaultLog,
  now = () => Date.now(),
  maxAgeSeconds = DEFAULT_MAX_AGE_SECONDS,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  seenDeliveries = new Map(),
} = {}) {
  if (!secret) throw new Error('Set INVYMATE_WEBHOOK_SECRET before starting the receiver.');

  return http.createServer(async (request, response) => {
    const path = new URL(request.url || '/', 'http://localhost').pathname;
    let rawBody = Buffer.alloc(0);
    let parsedBody = null;
    let requestLogged = false;

    try {
      rawBody = await readRequestBody(request, maxBodyBytes);
      parsedBody = rawBody.length ? parseJson(rawBody) : null;
      log({
        kind: 'request',
        method: request.method,
        path,
        headers: request.headers,
        rawBody: rawBody.toString('utf8'),
        json: parsedBody,
      });
      requestLogged = true;

      if (request.method === 'GET' && path === '/healthz') {
        sendJson(response, 200, { ok: true, seenDeliveries: seenDeliveries.size }, log);
        return;
      }

      if (request.method !== 'POST' || path !== '/webhook') {
        sendJson(response, 404, { error: 'Not found' }, log);
        return;
      }

      const deliveryId = getHeader(request, 'x-invymate-delivery-id');
      if (!deliveryId) {
        sendJson(response, 400, { error: 'Missing X-InvyMate-Delivery-Id header' }, log);
        return;
      }

      if (!verifyWebhookSignature(rawBody, getHeader(request, 'x-invymate-signature'), secret, now(), maxAgeSeconds)) {
        sendJson(response, 401, { error: 'Invalid signature' }, log);
        return;
      }

      if (!parsedBody || typeof parsedBody !== 'object' || Array.isArray(parsedBody)) {
        sendJson(response, 400, { error: 'Request body must be a JSON object' }, log);
        return;
      }

      const eventType = getHeader(request, 'x-invymate-event') || parsedBody.type || '';
      const isVerification = parsedBody.type === 'webhook.endpoint.verification';
      const challenge = parsedBody.data?.challenge;

      if (seenDeliveries.has(deliveryId)) {
        if (isVerification && typeof challenge === 'string' && challenge) {
          sendJson(response, 200, { challenge }, log);
          return;
        }
        sendJson(response, 200, { ok: true, duplicate: true, deliveryId }, log);
        return;
      }

      seenDeliveries.set(deliveryId, now());

      if (isVerification) {
        if (typeof challenge !== 'string' || !challenge) {
          sendJson(response, 400, { error: 'Verification challenge is missing' }, log);
          return;
        }
        sendJson(response, 200, { challenge }, log);
        return;
      }

      sendJson(response, 200, { ok: true, duplicate: false, deliveryId, eventType }, log);
    } catch (error) {
      if (!requestLogged) {
        log({
          kind: 'request',
          method: request.method,
          path,
          headers: request.headers,
          rawBody: rawBody.toString('utf8'),
          json: parsedBody,
        });
      }
      const status = Number.isInteger(error?.statusCode) ? error.statusCode : 500;
      sendJson(response, status, { error: status === 500 ? 'Internal server error' : error.message }, log);
    }
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const server = createWebhookServer({ secret: process.env.INVYMATE_WEBHOOK_SECRET });
  const host = process.env.HOST || '0.0.0.0';
  const port = Number(process.env.PORT || 8080);
  server.listen(port, host, () => {
    console.log(`[invymate-webhook] listening on http://${host}:${port}`);
  });
}
