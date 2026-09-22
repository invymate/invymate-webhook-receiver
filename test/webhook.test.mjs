import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { createWebhookServer, verifyWebhookSignature } from '../src/server.mjs';

const SECRET = 'local-example-secret';
const NOW_MS = 1_727_000_000_000;

function sign(body, timestamp = Math.floor(NOW_MS / 1000), secret = SECRET) {
  const value = Buffer.concat([Buffer.from(String(timestamp), 'ascii'), Buffer.from('.'), Buffer.from(body)]);
  return `t=${timestamp},v1=${crypto.createHmac('sha256', secret).update(value).digest('hex')}`;
}

async function withServer(options, callback) {
  const server = createWebhookServer(options);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');

  try {
    return await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

test('accepts a valid signature and rejects altered or stale requests', () => {
  const body = Buffer.from('{"type":"asset.created"}');
  const signature = sign(body);

  assert.equal(verifyWebhookSignature(body, signature, SECRET, NOW_MS), true);
  assert.equal(verifyWebhookSignature(Buffer.from('{"type":"person.created"}'), signature, SECRET, NOW_MS), false);
  assert.equal(verifyWebhookSignature(body, sign(body, Math.floor(NOW_MS / 1000) - 301), SECRET, NOW_MS), false);
});

test('echoes verification challenges and logs the request and response', async () => {
  const logs = [];
  const body = JSON.stringify({
    version: 'v1',
    type: 'webhook.endpoint.verification',
    eventId: 'event-1',
    data: { endpointId: 'endpoint-1', challenge: 'challenge-1' },
  });

  await withServer({ secret: SECRET, now: () => NOW_MS, log: (entry) => logs.push(entry) }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/webhook`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-invymate-event': 'webhook.endpoint.verification',
        'x-invymate-delivery-id': 'delivery-1',
        'x-invymate-signature': sign(body),
      },
      body,
    });

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { challenge: 'challenge-1' });
  });

  assert.equal(logs[0].kind, 'request');
  assert.equal(logs[0].rawBody, body);
  assert.equal(logs.at(-1).kind, 'response');
  assert.equal(logs.at(-1).status, 200);
  assert.equal(logs.at(-1).body, '{"challenge":"challenge-1"}');
});

test('returns duplicate for a repeated delivery ID', async () => {
  const body = JSON.stringify({ version: 'v1', type: 'asset.created', eventId: 'event-2', data: {} });

  await withServer({ secret: SECRET, now: () => NOW_MS, log: () => {} }, async (baseUrl) => {
    const request = () =>
      fetch(`${baseUrl}/webhook`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-invymate-event': 'asset.created',
          'x-invymate-delivery-id': 'delivery-2',
          'x-invymate-signature': sign(body),
        },
        body,
      });

    const first = await request();
    const second = await request();

    assert.equal(first.status, 200);
    assert.deepEqual(await first.json(), { ok: true, duplicate: false, deliveryId: 'delivery-2', eventType: 'asset.created' });
    assert.equal(second.status, 200);
    assert.deepEqual(await second.json(), { ok: true, duplicate: true, deliveryId: 'delivery-2' });
  });
});

test('rejects an invalid signature and logs the 401 response', async () => {
  const logs = [];

  await withServer({ secret: SECRET, now: () => NOW_MS, log: (entry) => logs.push(entry) }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/webhook`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-invymate-delivery-id': 'delivery-invalid',
        'x-invymate-signature': sign('{}', undefined, 'wrong-secret'),
      },
      body: '{}',
    });

    assert.equal(response.status, 401);
  });

  assert.equal(logs.at(-1).kind, 'response');
  assert.equal(logs.at(-1).status, 401);
});
