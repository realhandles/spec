# RealHandles protocol

The open format behind [RealHandles](https://realhandles.com): a portable,
self-verifying proof that a set of online accounts belongs to one holder of an
Ed25519 key.

The point of publishing this is simple. RealHandles is only trustworthy if you
do **not** have to trust RealHandles. A proof is a signed file; anyone can verify
it with standard cryptography, offline, with no dependency on our servers. **The
key is the identity, never a name, a domain, or a company.**

## What's here

- [`SPEC.md`](./SPEC.md) — the protocol: artifacts, the manifest payload, the
  `keyId` fingerprint, methods and trust tiers, and the verification algorithm.
- [`schema/realhandles-v1.json`](./schema/realhandles-v1.json) — the JSON Schema
  (also served at `https://realhandles.com/schema/realhandles-v1.json`).
- [`vectors/`](./vectors/) — signed example files and their expected results, so
  any implementation can prove it conforms.

## Reference implementation

[`@realhandles/verify`](https://github.com/realhandles/verify) is the reference
verifier: isomorphic, `jose`-only, and the same code RealHandles itself runs.

```ts
import { verifySignedManifest } from '@realhandles/verify';

const file = await fetch('https://realhandles.com/dvk/realhandles.json').then((r) => r.json());
const result = await verifySignedManifest(file);
// result.valid, result.keyId, result.manifest
```

## Regenerate the vectors

```bash
npm install
npm run generate
```

## License

MIT. Implement it, verify against it, build on it.
