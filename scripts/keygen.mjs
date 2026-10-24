// Generates the relay's RSA-4096 key pair on your machine and prints the
// private key (for `wrangler secret put RELAY_PRIVATE_KEY`) and its key id.
//
//   node scripts/keygen.mjs > relay-private.pem
//   npx wrangler secret put RELAY_PRIVATE_KEY < relay-private.pem
//   rm relay-private.pem
//
// The key id goes to stderr so it stays out of the file.
import { generateKeyPairSync, createHash } from 'node:crypto'

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 4096 })
const spki = publicKey.export({ type: 'spki', format: 'der' })
const kid = createHash('sha256').update(spki).digest('hex').slice(0, 16)
process.stdout.write(privateKey.export({ type: 'pkcs8', format: 'pem' }))
process.stderr.write(`relay key id: ${kid}\n`)
