# SpendMux key relay

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/peragolabs/spendmux-relay)

A Cloudflare Worker you run in your own account so SpendMux never holds your
provider keys. SpendMux stores only an envelope sealed to this relay's key,
signs every call it sends here, and the relay attaches the key and calls the
provider. It has no dependencies: `src/index.js` and `src/seal.js` are the
whole thing.

## Set up

You need a Cloudflare account and Node 22. The deploy button above creates the
Worker for you; you still set its three secrets below. By hand:

```sh
git clone https://github.com/peragolabs/spendmux-relay
cd spendmux-relay
node scripts/keygen.mjs > relay-private.pem      # prints the relay key id
npx wrangler secret put RELAY_PRIVATE_KEY < relay-private.pem
rm relay-private.pem
npx wrangler secret put SPENDMUX_PUBLIC_KEYS     # from SpendMux /keys → "My relay"
npx wrangler secret put SPENDMUX_ACCOUNT         # same place
npx wrangler deploy
```

Then open `https://<your relay>/seal`, check the key id matches the one
`keygen.mjs` printed, pick the provider, paste the key and press Seal. Paste
the envelope and your relay URL into SpendMux's Keys page under "My relay".

The key is typed into a page served by your relay, not by SpendMux, so a
tampered SpendMux page never sees it.

## What the relay checks

Before it opens a key, every call to `/v1/forward` must:

- carry an Ed25519 signature from a key in `SPENDMUX_PUBLIC_KEYS` over the
  account, method, target URL, timestamp, body hash and envelope hash
- be signed within the last 60 seconds
- name the account in `SPENDMUX_ACCOUNT`
- target a URL on the base URL sealed into the envelope (https only). The
  envelope's provider, base URL and auth style are bound into the AES-GCM
  encryption, so changing them makes the envelope fail to open
- fit under `DAILY_REQUEST_LIMIT` (default 10000 per UTC day, counted in a
  Durable Object; 0 turns it off)

Only a fixed set of headers is forwarded to the provider, redirects are not
followed, and errors from the relay itself carry an `x-spendmux-relay-error`
header so SpendMux can tell them from provider errors.

## Rotating

- **Relay key:** run `keygen.mjs` again, move the current key to
  `RELAY_PRIVATE_KEY_OLD`, set the new one as `RELAY_PRIVATE_KEY`, re-seal your
  keys on `/seal`, then delete `RELAY_PRIVATE_KEY_OLD`.
- **SpendMux's signing key:** SpendMux publishes the new public key on the Keys
  page; add it to `SPENDMUX_PUBLIC_KEYS` (comma-separated) and remove the old
  one when SpendMux has switched.

## Limits

- Bearer, `x-api-key` and `api-key` providers only. Bedrock and Vertex sign
  requests themselves and can't use a relay yet.
- The daily cap counts requests, not dollars. Dollar caps stay in SpendMux.
- Prompts and replies pass through SpendMux as before; the relay keeps the key
  out of SpendMux, not the traffic.

## Test

```sh
npm test    # node --test, no install needed
```

`test/vector.json` is a call signed by SpendMux's Go code, so the tests here
check that this relay accepts exactly what SpendMux sends.

## Reporting a security issue

Please report security issues privately to security@peragolabs.com, not in a public issue.

## License

MIT
