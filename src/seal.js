// The /seal page. It runs on the customer's relay domain, so the provider key
// is typed into a page SpendMux does not serve and cannot change. The browser
// encrypts the key with this relay's public key and shows the envelope to
// paste into SpendMux. Nothing is sent anywhere.

// Base URLs match SpendMux's provider registry. "Other" takes any https URL.
const PROVIDERS = [
  ['openai', 'OpenAI', 'https://api.openai.com/v1', 'bearer'],
  ['anthropic', 'Anthropic', 'https://api.anthropic.com', 'x-api-key'],
  ['google', 'Google Gemini', 'https://generativelanguage.googleapis.com/v1beta/openai', 'bearer'],
  ['xai', 'xAI (Grok)', 'https://api.x.ai/v1', 'bearer'],
  ['mistral', 'Mistral', 'https://api.mistral.ai/v1', 'bearer'],
  ['deepseek', 'DeepSeek', 'https://api.deepseek.com/v1', 'bearer'],
  ['groq', 'Groq', 'https://api.groq.com/openai/v1', 'bearer'],
  ['together', 'Together', 'https://api.together.xyz/v1', 'bearer'],
  ['fireworks', 'Fireworks', 'https://api.fireworks.ai/inference/v1', 'bearer'],
  ['openrouter', 'OpenRouter', 'https://openrouter.ai/api/v1', 'bearer'],
  ['azure', 'Azure OpenAI', '', 'api-key'],
  ['custom', 'Other OpenAI-compatible', '', 'bearer'],
]

// sealKey is the whole seal: a fresh AES-256-GCM key encrypts the provider
// key with the metadata as additional data, and RSA-OAEP wraps the AES key.
// The page embeds this function's source, so the tests exercise the same code.
export async function sealKey(spkiB64, kid, metaObj, key) {
  const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)))
  const meta = JSON.stringify(metaObj)
  const der = Uint8Array.from(atob(spkiB64), (c) => c.charCodeAt(0))
  const pub = await crypto.subtle.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt'])
  const dk = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(meta) }, dk, new TextEncoder().encode(key))
  const wk = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, await crypto.subtle.exportKey('raw', dk))
  return JSON.stringify({ v: 1, alg: 'RSA-OAEP-256+A256GCM', kid, meta, wk: b64(wk), iv: b64(iv), ct: b64(ct) })
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])

export function sealPage({ kid, spki, nonce }) {
  const options = PROVIDERS.map(([id, name]) => `<option value="${esc(id)}">${esc(name)}</option>`).join('')
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Seal a provider key</title><link rel="icon" href="data:,">
<style nonce="${esc(nonce)}">
body{font:15px/1.5 system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#1a1a1a;background:#fff}
@media (prefers-color-scheme:dark){body{color:#eee;background:#141414}input,select,textarea{background:#1f1f1f;color:#eee;border-color:#444}}
label{display:block;margin:16px 0 4px;font-weight:600}input,select,textarea{width:100%;box-sizing:border-box;padding:8px;border:1px solid #bbb;border-radius:6px;font:inherit}
textarea{font:12px/1.4 ui-monospace,monospace;height:140px}button{margin-top:20px;padding:10px 16px;border:0;border-radius:6px;background:#2563eb;color:#fff;font:inherit;font-weight:600;cursor:pointer}
.note{color:#777;font-size:13px}code{font:13px ui-monospace,monospace}
</style></head><body>
<h1>Seal a provider key</h1>
<p>Your key is encrypted in this browser with this relay's public key. Only this relay can open it. Paste the result into SpendMux's Keys page.</p>
<p class="note">Relay key id <code>${esc(kid)}</code>. It should match the id <code>keygen.mjs</code> printed.</p>
<label for="provider">Provider</label><select id="provider">${options}</select>
<label for="base">Base URL</label><input id="base" placeholder="https://…" autocomplete="off">
<p class="note">The relay will only ever send this key to this URL.</p>
<label for="key">API key</label><input id="key" type="password" autocomplete="off">
<button id="seal" type="button">Seal</button>
<label for="out">Envelope</label><textarea id="out" readonly></textarea>
<p class="note" id="status"></p>
<script nonce="${esc(nonce)}">
// Wrangler bundles with esbuild's keepNames, which rewrites sealKey's source to
// call a __name helper that exists only in the Worker bundle. Define it here.
const __name = (f) => f;
const PROVIDERS = ${JSON.stringify(PROVIDERS)};
const SPKI = ${JSON.stringify(spki)};
const KID = ${JSON.stringify(kid)};
const $ = (id) => document.getElementById(id);
const pick = () => { const p = PROVIDERS.find((x) => x[0] === $('provider').value); $('base').value = p[2]; };
$('provider').addEventListener('change', pick); pick();
$('seal').addEventListener('click', async () => {
  const p = PROVIDERS.find((x) => x[0] === $('provider').value);
  const key = $('key').value.trim(), base = $('base').value.trim().replace(/\\/+$/, '');
  if (!key) { $('status').textContent = 'Paste a key first.'; return; }
  try { if (new URL(base).protocol !== 'https:') throw 0; } catch { $('status').textContent = 'Base URL must start with https://'; return; }
  $('out').value = await sealKey(SPKI, KID, { provider: p[0], base_url: base, auth: p[3], hint: '…' + key.slice(-4) }, key);
  $('key').value = '';
  $('status').textContent = 'Sealed. The key field is cleared; copy the envelope into SpendMux.';
});
${sealKey.toString()}
</script></body></html>`
}
