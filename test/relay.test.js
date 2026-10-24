// Run with: node --test relay/test
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { generateKeyPairSync } from 'node:crypto'

import worker, { RelayCounter, signedMessage, targetAllowed, loadKey, b64encode } from '../src/index.js'
import { sealKey, sealPage } from '../src/seal.js'

const vector = JSON.parse(readFileSync(new URL('./vector.json', import.meta.url), 'utf8'))
const enc = new TextEncoder()

test('a call signed by SpendMux (Go) verifies here', async () => {
  const envelope = Buffer.from(vector.envelope, 'base64url').toString('utf8')
  const msg = await signedMessage({ account: vector.account, method: vector.method, target: vector.target, ts: vector.timestamp, body: enc.encode(vector.body), envelope })
  const pub = await crypto.subtle.importKey('raw', Buffer.from(vector.public_key, 'base64'), { name: 'Ed25519' }, false, ['verify'])
  assert.ok(await crypto.subtle.verify({ name: 'Ed25519' }, pub, Buffer.from(vector.signature, 'base64'), msg))
})

test('targetAllowed keeps the key on its sealed base URL', () => {
  const base = 'https://api.openai.com/v1'
  assert.ok(targetAllowed('https://api.openai.com/v1/chat/completions', base))
  assert.ok(targetAllowed('https://api.openai.com/v1', base + '/'))
  assert.ok(!targetAllowed('https://api.openai.com/v1.evil.com/x', base))
  assert.ok(!targetAllowed('https://api.openai.com/v2/chat', base))
  assert.ok(!targetAllowed('https://evil.example.com/v1/chat/completions', base))
  assert.ok(!targetAllowed('http://api.openai.com/v1/chat/completions', base))
  assert.ok(!targetAllowed('https://user:pw@api.openai.com/v1/chat', base))
  assert.ok(!targetAllowed('https://api.openai.com.evil.com/v1/chat', base))
})

// A relay with a fresh RSA key, a SpendMux signing key, and fetch stubbed so
// nothing leaves the test.
async function setup() {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' })
  const { kid, spki } = await loadKey(pem)
  const signer = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const pub = b64encode(new Uint8Array(await crypto.subtle.exportKey('raw', signer.publicKey)))
  const env = { RELAY_PRIVATE_KEY: pem, SPENDMUX_PUBLIC_KEYS: pub, SPENDMUX_ACCOUNT: 'acct-1', DAILY_REQUEST_LIMIT: '0' }
  const meta = { provider: 'openai', base_url: 'https://api.openai.com/v1', auth: 'bearer', hint: '…cret' }
  const envelope = await sealKey(spki, kid, meta, 'sk-test-secret')
  const sent = []
  globalThis.fetch = async (url, init) => {
    sent.push({ url, init })
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json', 'set-cookie': 'a=b' } })
  }
  const call = async (over = {}) => {
    const o = { account: 'acct-1', target: 'https://api.openai.com/v1/chat/completions', ts: String(Math.floor(Date.now() / 1000)), body: '{"model":"gpt-4o-mini"}', envelope, method: 'POST', signedTarget: undefined, ...over }
    const msg = await signedMessage({ account: o.account, method: o.method, target: o.signedTarget || o.target, ts: o.ts, body: enc.encode(o.body), envelope: o.envelope })
    const sig = b64encode(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, signer.privateKey, msg)))
    const headers = {
      'content-type': 'application/json',
      'x-spendmux-account': o.account,
      'x-spendmux-target': o.target,
      'x-spendmux-timestamp': o.ts,
      'x-spendmux-envelope': Buffer.from(o.envelope).toString('base64url'),
      'x-spendmux-signature': o.signature || sig,
      authorization: 'Bearer smuggled',
      'cf-connecting-ip': '1.2.3.4',
    }
    return worker.fetch(new Request('https://relay.test/v1/forward', { method: o.method, headers, body: o.body }), env)
  }
  return { env, call, sent, envelope, kid, spki, meta }
}

test('a valid call reaches the provider with the key attached', async () => {
  const { call, sent } = await setup()
  const res = await call()
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('set-cookie'), null)
  assert.equal(sent.length, 1)
  assert.equal(sent[0].url, 'https://api.openai.com/v1/chat/completions')
  assert.equal(sent[0].init.redirect, 'manual')
  const h = sent[0].init.headers
  assert.equal(h.get('authorization'), 'Bearer sk-test-secret')
  assert.equal(h.get('content-type'), 'application/json')
  assert.equal(h.get('cf-connecting-ip'), null)
  for (const [k] of h) assert.ok(!k.startsWith('x-spendmux'), k)
  assert.equal(new TextDecoder().decode(sent[0].init.body), '{"model":"gpt-4o-mini"}')
})

test('the relay refuses calls it should not make', async (t) => {
  const { call, sent, envelope, kid, spki, meta } = await setup()
  const cases = {
    'wrong account': [{ account: 'acct-2' }, 403, 'wrong_account'],
    'stale timestamp': [{ ts: String(Math.floor(Date.now() / 1000) - 120) }, 401, 'stale_signature'],
    'bad signature': [{ signature: b64encode(new Uint8Array(64)) }, 401, 'bad_signature'],
    'target changed after signing': [{ signedTarget: 'https://api.openai.com/v1/chat/completions', target: 'https://api.openai.com/v1/embeddings' }, 401, 'bad_signature'],
    'target off the sealed base URL': [{ target: 'https://evil.example.com/v1/chat/completions' }, 403, 'target_not_sealed'],
  }
  // An envelope whose metadata was edited to point somewhere else no longer opens.
  const e = JSON.parse(envelope)
  e.meta = JSON.stringify({ ...meta, base_url: 'https://evil.example.com' })
  cases['metadata edited'] = [{ envelope: JSON.stringify(e), target: 'https://evil.example.com/steal' }, 400, 'bad_envelope']
  cases['sealed for another relay'] = [{ envelope: JSON.stringify({ ...JSON.parse(envelope), kid: 'ffffffffffffffff' }) }, 400, 'unknown_kid']
  for (const [name, [over, status, code]] of Object.entries(cases)) {
    await t.test(name, async () => {
      const res = await call(over)
      assert.equal(res.status, status)
      assert.equal(res.headers.get('x-spendmux-relay-error'), code)
    })
  }
  assert.equal(sent.length, 0, 'no refused call may reach the provider')
  assert.ok(kid && spki)
})

test('the daily cap stops calls once used up', async () => {
  const store = new Map()
  const counter = new RelayCounter({ storage: { get: async (k) => store.get(k), put: async (k, v) => store.set(k, v) } })
  const take = () => counter.fetch(new Request('https://counter/take', { method: 'POST', body: JSON.stringify({ limit: 2 }) })).then((r) => r.json())
  assert.equal((await take()).ok, true)
  assert.equal((await take()).ok, true)
  assert.equal((await take()).ok, false)

  const { env, call } = await setup()
  env.DAILY_REQUEST_LIMIT = '1'
  env.RELAY_COUNTER = { idFromName: () => 'daily', get: () => ({ fetch: (url, init) => counter.fetch(new Request(url, init)) }) }
  const res = await call()
  assert.equal(res.status, 429)
  assert.equal(res.headers.get('x-spendmux-relay-error'), 'relay_daily_cap')
})

test('the seal page carries only the public key and locks down scripts', async () => {
  const { env } = await setup()
  const res = await worker.fetch(new Request('https://relay.test/seal'), env)
  const html = await res.text()
  assert.match(res.headers.get('content-security-policy'), /script-src 'nonce-/)
  assert.ok(!html.includes('PRIVATE KEY'))
  assert.ok(html.includes('async function sealKey'))
  assert.ok(sealPage({ kid: 'k', spki: 's', nonce: 'n' }).includes('nonce="n"'))
})
