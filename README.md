# InvyMate webhook receiver example

A small Node.js 20 example application for receiving and validating InvyMate webhooks.

It demonstrates:

- HMAC-SHA256 signature validation;
- five-minute timestamp protection;
- verification challenge handling;
- delivery-ID idempotency;
- request and response debug logging.

This is a learning and testing example. The deduplication store is in memory, so replace it with Redis or a database before using this pattern in production.

## Requirements

- Node.js 20+
- An InvyMate workspace with the Webhooks feature

## Run locally

```bash
npm test

export INVYMATE_WEBHOOK_SECRET='<secret shown by InvyMate>'
npm start
```

The receiver listens on `http://localhost:8080` by default.

Check the health endpoint:

```bash
curl http://127.0.0.1:8080/healthz
```

## Connect it to InvyMate

Expose the local server through a temporary HTTPS tunnel:

```bash
ngrok http 8080
```

In InvyMate, open **Configuration → Webhooks** and create an endpoint using:

```text
https://<your-tunnel-host>/webhook
```

Select one or more events, save the secret in `INVYMATE_WEBHOOK_SECRET`, and click **Verify**. The example validates the signed verification request and returns the required `data.challenge` value.

After verification, create or update an asset/person that matches one of the selected event types. The terminal prints the full incoming request and outgoing response.

## Signature contract

InvyMate sends:

```text
X-InvyMate-Signature: t=<unix-seconds>,v1=<hex-hmac>
```

The signature is calculated as:

```text
HMAC-SHA256(webhook_secret, timestamp + "." + exact_raw_request_body)
```

The example verifies the signature before parsing JSON, rejects signatures older than five minutes, and uses `X-InvyMate-Delivery-Id` to handle duplicate deliveries safely.

See the complete customer documentation at [invymate.com/docs/webhooks](https://invymate.com/docs/webhooks).

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `INVYMATE_WEBHOOK_SECRET` | — | Secret shown once when the endpoint is created |
| `HOST` | `0.0.0.0` | HTTP bind host |
| `PORT` | `8080` | HTTP bind port |

Do not commit the secret or use the example's in-memory store as a production persistence layer.
