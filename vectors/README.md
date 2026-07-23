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

A stricter verifier may also confirm the JSON validates against
[`../schema/realhandles-v1.json`](../schema/realhandles-v1.json), but schema
validity is never a substitute for checking the signature.

Regenerate with `npm install && npm run generate` from the repo root. The keys
are random per run, so the exact bytes change but the expected results do not.
