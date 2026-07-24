# Conformance vectors

Each file is a complete RealHandles artifact (see [`../SPEC.md`](../SPEC.md)). A
conforming verifier MUST produce the stated result. The valid vector embeds its
own public key, so it verifies with no external material.

| File | Expected | Why |
| --- | --- | --- |
| `valid-manifest.json` | **valid** | Correctly signed; `subject.keyId` is the fingerprint of the embedded key. |
| `wrong-keyid.json` | **invalid** | Signature is good, but `subject.keyId` is not the fingerprint of the key (verification step 4). |
| `tampered-signature.json` | **invalid** | Payload is intact but the JWS signature was altered (verification step 2). |
| `valid-chain.json` | **valid chain** | A two-entry append-only sigchain (`{versions:[{seq,file}]}`). `verifyChain` accepts it: seq 0 then 1, `prev` links by hash, one key throughout. |
| `valid-rotation-chain.json` | **valid chain, key rotated** | Genesis by key A, then an entry signed by a new key B with a `rotation` A authorized. `verifyChain` accepts it (pin the genesis) and reports B as the current key. |
| `valid-recovery-chain.json` | **valid chain, key recovered** | Genesis by key A designates recovery key R. Key A is then lost, and a new key C takes over authorized by R, not by A. `verifyChain` accepts it and reports C as the current key. |
| `forged-recovery-chain.json` | **invalid** (`mustFail: true`) | The same shape, but the identity never designated anyone: the forging entry names its own accomplice key in a policy it declares about itself. A verifier that accepts this hands identities to anyone who asks. |

A stricter verifier may also confirm the JSON validates against
[`../schema/realhandles-v1.json`](../schema/realhandles-v1.json), but schema
validity is never a substitute for checking the signature.

Regenerate with `npm install && npm run generate` from the repo root. The keys
are random per run, so the exact bytes change but the expected results do not.
