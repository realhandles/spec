// Regenerate the conformance vectors. Run: `npm install && npm run generate`.
//
// Produces one valid signed manifest and two invalid variants a conforming
// verifier must reject. The valid vector embeds a freshly generated key, so it
// is fully self-contained (no external key material needed to verify it).
import { CompactSign, generateKeyPair, exportJWK } from 'jose';
import { webcrypto } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const SCHEMA = 'https://realhandles.com/schema/realhandles-v1.json';
const enc = new TextEncoder();

function b64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

// keyId = base64url(SHA-256(canonical {crv,kty,x})), matching the spec (section 2).
async function keyIdFromJwk(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  const digest = await webcrypto.subtle.digest('SHA-256', enc.encode(canonical));
  return b64u(new Uint8Array(digest));
}

const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
const publicKeyJwk = await exportJWK(publicKey);
const keyId = await keyIdFromJwk(publicKeyJwk);

const manifest = {
  version: '1',
  subject: { username: 'dvk', displayName: 'David V. Kimball', publicKey: publicKeyJwk, keyId },
  accounts: [
    { platform: 'github', handle: 'davidvkimball', profileUrl: 'https://github.com/davidvkimball', method: 'oauth', verifiedAt: '2026-01-01T00:00:00.000Z' },
    { platform: 'domain', handle: 'davidvkimball.com', profileUrl: 'https://davidvkimball.com', method: 'domain-control', verifiedAt: '2026-01-01T00:00:00.000Z' },
  ],
  issued: '2026-01-01T00:00:00.000Z',
  statement: 'These accounts belong to the holder of this key.',
};

async function sign(payload) {
  return await new CompactSign(enc.encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'EdDSA', kid: payload.subject.keyId })
    .sign(privateKey);
}

function write(name, obj) {
  writeFileSync(join(here, name), JSON.stringify(obj, null, 2) + '\n');
}

// 1) Valid: verifies true.
const validJws = await sign(manifest);
write('valid-manifest.json', { $schema: SCHEMA, jws: validJws, manifest, publicKeyJwk, keyId });

// 2) Wrong keyId: signed correctly, but subject.keyId is not the fingerprint of
//    the key, so step 4 of verification fails.
const wrongManifest = { ...manifest, subject: { ...manifest.subject, keyId: 'not-the-real-fingerprint-000000000000000000' } };
const wrongJws = await sign(wrongManifest);
write('wrong-keyid.json', { $schema: SCHEMA, jws: wrongJws, manifest: wrongManifest, publicKeyJwk, keyId: wrongManifest.subject.keyId });

// 3) Tampered signature: valid payload, corrupted signature segment, so step 2
//    (signature check) fails.
const [h, p, s] = validJws.split('.');
const badSig = s.slice(0, -3) + (s.endsWith('aaa') ? 'bbb' : 'aaa');
write('tampered-signature.json', { $schema: SCHEMA, jws: [h, p, badSig].join('.'), manifest, publicKeyJwk, keyId });

console.log('Wrote valid-manifest.json, wrong-keyid.json, tampered-signature.json');
