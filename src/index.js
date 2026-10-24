// SpendMux key relay: a Cloudflare Worker the customer runs in their own
// account. It holds the only private key that can open their sealed provider
// keys. SpendMux sends each provider request here, signed, with the sealed
// key; the relay checks the signature, opens the key, attaches it and calls
// the provider. SpendMux never sees a provider key.
//
// Settings (wrangler secrets unless noted):
//   RELAY_PRIVATE_KEY       PKCS#8 PEM, RSA-4096, from scripts/keygen.mjs
//   RELAY_PRIVATE_KEY_OLD   optional, the previous key while re-sealing after a rotation
//   SPENDMUX_PUBLIC_KEYS    base64 Ed25519 public key(s) from SpendMux's Keys page, comma-separated
//   SPENDMUX_ACCOUNT        your SpendMux account id, from the same page
//   DAILY_REQUEST_LIMIT     var, default 10000; 0 turns the cap off
//
// No dependencies: everything here is WebCrypto and fetch.

import { sealPage } from './seal.js'

export const ENVELOPE_ALG = 'RSA-OAEP-256+A256GCM'
export const SIGNATURE_VERSION = 'spendmux-relay-v1'
const MAX_SKEW_SECONDS = 60
const AUTH_STYLES = new Set(['bearer', 'x-api-key', 'api-key'])
// Headers SpendMux may pass to the provider. Everything else is dropped, so a
// request can't smuggle its own credentials or Cloudflare headers through.
const FORWARD_HEADERS = ['content-type', 'accept', 'anthropic-version', 'anthropic-beta', 'openai-organization', 'openai-project', 'openai-beta', 'user-agent']

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url)
    try {
      if (request.method === 'GET' && url.pathname === '/health') return text('ok')
      if (request.method === 'GET' && url.pathname === '/public-key') return publicKeyResponse(env)
      if (request.method === 'GET' && url.pathname === '/seal') return sealResponse(env)
      if (url.pathname === '/v1/forward') return await forward(request, env)
      return relayError(404, 'not_found', 'unknown path')
    } catch (err) {
      if (err instanceof RelayError) return relayError(err.status, err.code, err.message)
      console.error('relay_failed', err && err.message)
      return relayError(500, 'relay_failed', 'relay failed')
    }
  },
}

export class RelayCounter {
  constructor(state) {
    this.state = state
  }

  // POST {limit} → {ok, count}. A Durable Object runs one request at a time,
  // so the read and the write can't interleave across Worker instances.
  async fetch(request) {
    const { limit } = await request.json()
    const day = new Date().toISOString().slice(0, 10)
    const stored = (await this.state.storage.get('day')) || { day, count: 0 }
    const count = stored.day === day ? stored.count : 0
    if (limit > 0 && count >= limit) return Response.json({ ok: false, count })
    await this.state.storage.put('day', { day, count: count + 1 })
    return Response.json({ ok: true, count: count + 1 })
  }
}

class RelayError extends Error {
  constructor(status, code, message) {
    super(message)
    this.status = status
    this.code = code
  }
}

async function forward(request, env) {
  if (request.method !== 'POST' && request.method !== 'GET') throw new RelayError(405, 'method_not_allowed', 'POST or GET only')
  const body = request.method === 'GET' ? new Uint8Array() : new Uint8Array(await request.arrayBuffer())
  const call = await verifyCall(request, body, env, Math.floor(Date.now() / 1000))
  await takeDailySlot(env)

  const headers = new Headers()
  for (const name of FORWARD_HEADERS) {
    const v = request.headers.get(name)
    if (v) headers.set(name, v)
  }
  applyAuth(headers, call.meta.auth, call.key)
  const upstream = await fetch(call.target, {
    method: request.method,
    headers,
    body: request.method === 'GET' ? undefined : body,
    redirect: 'manual', // a redirect could carry the key header somewhere else
  })
  const out = new Headers(upstream.headers)
  out.delete('set-cookie')
  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: out })
}

// verifyCall checks everything about a forwarded call before any key is
// opened, and returns the target, the envelope's public metadata and the key.
export async function verifyCall(request, body, env, now) {
  const h = (name) => (request.headers.get(name) || '').trim()
  const account = h('x-spendmux-account')
  const target = h('x-spendmux-target')
  const ts = h('x-spendmux-timestamp')
  const envelopeB64 = h('x-spendmux-envelope')
  const signature = h('x-spendmux-signature')
  if (!account || !target || !ts || !envelopeB64 || !signature) throw new RelayError(401, 'unsigned', 'missing SpendMux signature headers')

  if (!env.SPENDMUX_ACCOUNT || account !== env.SPENDMUX_ACCOUNT.trim()) throw new RelayError(403, 'wrong_account', 'this relay belongs to another SpendMux account')
  if (!/^\d{1,12}$/.test(ts) || Math.abs(now - Number(ts)) > MAX_SKEW_SECONDS) throw new RelayError(401, 'stale_signature', 'signature is too old or from the future; check the server clock')

  const envelopeJSON = new TextDecoder().decode(b64decode(envelopeB64, true))
  const message = await signedMessage({ account, method: request.method, target, ts, body, envelope: envelopeJSON })
  if (!(await verifyAny(env.SPENDMUX_PUBLIC_KEYS, signature, message))) throw new RelayError(401, 'bad_signature', 'signature does not match a pinned SpendMux key')

  const envelope = parseEnvelope(envelopeJSON)
  const meta = parseMeta(envelope.meta)
  if (!targetAllowed(target, meta.base_url)) throw new RelayError(403, 'target_not_sealed', 'target is not on the base URL sealed with this key')
  const key = await openEnvelope(envelope, env)
  return { target, meta, key }
}

export async function signedMessage({ account, method, target, ts, body, envelope }) {
  const lines = [SIGNATURE_VERSION, account, method.toUpperCase(), target, ts, await sha256Hex(body), await sha256Hex(new TextEncoder().encode(envelope))]
  return new TextEncoder().encode(lines.join('\n'))
}

async function verifyAny(keysSetting, signatureB64, message) {
  let sig
  try {
    sig = b64decode(signatureB64)
  } catch {
    return false
  }
  for (const k of String(keysSetting || '').split(',').map((s) => s.trim()).filter(Boolean)) {
    try {
      const pub = await crypto.subtle.importKey('raw', b64decode(k), { name: 'Ed25519' }, false, ['verify'])
      if (await crypto.subtle.verify({ name: 'Ed25519' }, pub, sig, message)) return true
    } catch {
      // a malformed pinned key is skipped; the others may still match
    }
  }
  return false
}

export function parseEnvelope(json) {
  let e
  try {
    e = JSON.parse(json)
  } catch {
    throw new RelayError(400, 'bad_envelope', 'envelope is not JSON')
  }
  if (!e || e.v !== 1 || e.alg !== ENVELOPE_ALG || typeof e.meta !== 'string') throw new RelayError(400, 'bad_envelope', 'unsupported envelope')
  for (const f of ['kid', 'wk', 'iv', 'ct']) {
    if (typeof e[f] !== 'string' || !e[f]) throw new RelayError(400, 'bad_envelope', `envelope is missing ${f}`)
  }
  return e
}

export function parseMeta(metaJSON) {
  let m
  try {
    m = JSON.parse(metaJSON)
  } catch {
    throw new RelayError(400, 'bad_envelope', 'envelope meta is not JSON')
  }
  if (!m || typeof m.provider !== 'string' || typeof m.base_url !== 'string' || !AUTH_STYLES.has(m.auth)) throw new RelayError(400, 'bad_envelope', 'envelope meta is incomplete')
  return m
}

// targetAllowed: https only, and on the sealed base URL at a path boundary,
// so "https://api.openai.com/v1" doesn't also allow "https://api.openai.com/v1.evil.com".
export function targetAllowed(target, baseURL) {
  let t, b
  try {
    t = new URL(target)
    b = new URL(baseURL)
  } catch {
    return false
  }
  if (t.protocol !== 'https:' || b.protocol !== 'https:' || t.username || t.password) return false
  if (t.origin !== b.origin) return false
  const base = b.pathname.replace(/\/+$/, '')
  return t.pathname === base || t.pathname.startsWith(base + '/')
}

async function openEnvelope(e, env) {
  for (const pem of [env.RELAY_PRIVATE_KEY, env.RELAY_PRIVATE_KEY_OLD]) {
    if (!pem) continue
    const { kid, privateKey } = await loadKey(pem)
    if (kid !== e.kid) continue
    try {
      const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, b64decode(e.wk))
      const dataKey = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt'])
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64decode(e.iv), additionalData: new TextEncoder().encode(e.meta) },
        dataKey,
        b64decode(e.ct),
      )
      return new TextDecoder().decode(plain)
    } catch {
      throw new RelayError(400, 'bad_envelope', 'envelope does not open; it was changed or sealed for another relay')
    }
  }
  throw new RelayError(400, 'unknown_kid', 'envelope was sealed with a key this relay does not hold')
}

const keyCache = new Map()

// loadKey imports a PKCS#8 PEM and derives its kid from the public half,
// the same way the seal page and SpendMux do.
export async function loadKey(pem) {
  if (keyCache.has(pem)) return keyCache.get(pem)
  const der = b64decode(pem.replace(/\\n/g, '\n').replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''))
  const privateKey = await crypto.subtle.importKey('pkcs8', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt'])
  const jwk = await crypto.subtle.exportKey('jwk', privateKey)
  const publicKey = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RSA-OAEP-256', ext: true }, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt'])
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey))
  const kid = (await sha256Hex(spki)).slice(0, 16)
  const loaded = { kid, privateKey, spki: b64encode(spki) }
  keyCache.set(pem, loaded)
  return loaded
}

export function applyAuth(headers, style, key) {
  switch (style) {
    case 'x-api-key':
      headers.set('x-api-key', key)
      if (!headers.has('anthropic-version')) headers.set('anthropic-version', '2023-06-01')
      return
    case 'api-key':
      headers.set('api-key', key)
      return
    default:
      headers.set('authorization', 'Bearer ' + key)
  }
}

async function takeDailySlot(env) {
  const limit = env.DAILY_REQUEST_LIMIT === undefined || env.DAILY_REQUEST_LIMIT === '' ? 10000 : Number(env.DAILY_REQUEST_LIMIT)
  if (!(limit > 0) || !env.RELAY_COUNTER) return
  const stub = env.RELAY_COUNTER.get(env.RELAY_COUNTER.idFromName('daily'))
  const res = await stub.fetch('https://counter/take', { method: 'POST', body: JSON.stringify({ limit }) })
  const { ok } = await res.json()
  if (!ok) throw new RelayError(429, 'relay_daily_cap', `this relay's daily cap of ${limit} requests is used up`)
}

async function publicKeyResponse(env) {
  if (!env.RELAY_PRIVATE_KEY) throw new RelayError(503, 'not_configured', 'RELAY_PRIVATE_KEY is not set')
  const { kid, spki } = await loadKey(env.RELAY_PRIVATE_KEY)
  return Response.json({ alg: ENVELOPE_ALG, kid, spki })
}

async function sealResponse(env) {
  if (!env.RELAY_PRIVATE_KEY) throw new RelayError(503, 'not_configured', 'RELAY_PRIVATE_KEY is not set')
  const { kid, spki } = await loadKey(env.RELAY_PRIVATE_KEY)
  const nonce = b64encode(crypto.getRandomValues(new Uint8Array(16)))
  return new Response(sealPage({ kid, spki, nonce }), {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': `default-src 'none'; img-src data:; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff',
      'cache-control': 'no-store',
    },
  })
}

function relayError(status, code, message) {
  return Response.json({ error: { message: 'relay: ' + message, type: 'relay_error', code } }, { status, headers: { 'x-spendmux-relay-error': code } })
}

function text(s) {
  return new Response(s, { headers: { 'content-type': 'text/plain' } })
}

async function sha256Hex(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function b64decode(s, urlSafe = false) {
  let t = s.trim()
  if (urlSafe) t = t.replace(/-/g, '+').replace(/_/g, '/')
  while (t.length % 4) t += '='
  const bin = atob(t)
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

export function b64encode(bytes) {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}
