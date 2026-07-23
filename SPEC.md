# RealHandles Protocol, v1

RealHandles is a portable identity format. A **proof** is a small JSON file whose
authoritative element is a compact JWS signed by an Ed25519 key that only the
owner holds. Anyone can verify a proof with standard cryptography, offline, and
without trusting or reaching realhandles.com.

The one invariant everything follows: **the key is the identity.** Verification
follows the key fingerprint (`keyId`), never a username, a domain, or a server. A
lapsed or hijacked domain can never transfer an identity, because it cannot
produce the signature.

- Signature algorithm: **EdDSA** over **Ed25519** (RFC 8037), as a compact JWS.
- Canonical schema: `https://realhandles.com/schema/realhandles-v1.json` (in
  [`schema/`](./schema/realhandles-v1.json)).
- Reference implementation of verification:
  [`@realhandles/verify`](https://github.com/realhandles/verify).

## 1. Artifacts

A RealHandles file is one of two shapes (`oneOf` in the schema):

1. A **signed manifest file** — the full, self-contained proof.
2. A **pointer file** — a signed, hosted-once anchor that points to the
   canonical manifest.

In both, the compact JWS in `jws` is authoritative. The sibling JSON fields
(`manifest`, `pointer`, `publicKeyJwk`, `keyId`) are a convenience mirror for
humans and MUST NOT be trusted over the decoded, signature-verified payload. A
verifier that disagrees with the mirror ignores the mirror.

### 1.1 Signed manifest file

```json
{
  "$schema": "https://realhandles.com/schema/realhandles-v1.json",
  "jws": "<compact JWS, authoritative>",
  "manifest": { "...": "convenience mirror of the signed payload" },
  "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "keyId": "..."
}
```

### 1.2 Manifest payload (the JWS payload)

| Field | Required | Notes |
| --- | --- | --- |
| `version` | yes | `"1"`. |
| `subject.username` | yes | The handle at `realhandles.com/<username>`. |
| `subject.displayName` | no | Human name. |
| `subject.publicKey` | yes | Ed25519 public JWK (`kty:"OKP"`, `crv:"Ed25519"`, `x`). |
| `subject.keyId` | yes | Fingerprint of `publicKey` (see 2). |
| `accounts` | yes | Array of account claims (see 1.3). |
| `disavowed` | no | Signed "not me" statements (see 1.4). |
| `anchor` | no | One rotatable pointer (see 1.5). Never the identity. |
| `issued` | yes | ISO 8601 timestamp. |
| `statement` | yes | Human-readable claim. |
| `seq` | no | Sigchain position: 0-based, +1 per re-sign. Missing = genesis (0). See 4.1. |
| `prev` | no | `base64url(SHA-256(previous manifest JWS))`, or null at genesis. |

### 1.3 Account claim

| Field | Required | Notes |
| --- | --- | --- |
| `platform` | yes | e.g. `"github"`, `"x"`, or `"domain"` for a controlled domain. |
| `handle` | yes | Username on that platform, or the domain itself. |
| `profileUrl` | yes | Link to the account. |
| `method` | yes | How control was established (see 3). |
| `verifiedAt` | yes | ISO 8601 timestamp. |
| `entity` | no | `"organization"` or `"server"` the holder runs. |
| `image` | no | Logo/icon URL for an org/server account. |
| `builder` | no | For a `rel="me"` link-in-bio, the recognized builder (cosmetic only, never a trust signal). |

### 1.4 Disavowal

A signed statement that something is NOT the subject: `kind` (`"account"` or
`"platform"`), `platform`, optional `handle`, `url`, and `note`. Additive to the
key model, it is just another signed statement.

### 1.5 Anchor

An optional rotatable pointer to a hosted copy: `url`, `kind` (`"domain"`,
`"gist"`, `"other"`), optional `domain`. The anchor is durability, not identity.
Losing it never moves the identity.

### 1.6 Pointer file

A "sign once, host once" anchor. Its payload has `type: "anchor-pointer"`,
`keyId`, `publicKey`, `canonical` (the always-current manifest URL, e.g.
`https://realhandles.com/<user>/realhandles.json`), and `issued`. It proves
control of the hosting location and points to the canonical proof.

## 2. keyId

```
keyId = base64url( SHA-256( JSON({ "crv": crv, "kty": kty, "x": x }) ) )
```

The JWK is canonicalized to exactly `{crv, kty, x}` in that key order before
hashing, so the fingerprint is identical across implementations. This is the
value verifiers pin to mean "trust this key."

## 3. Methods and trust tiers

Every account records the `method` by which control was established. Methods
split into two tiers:

- **Verified** (a first party or the platform confirms who controls the account):
  `oauth`, `tweet-proof`, `post-proof`, `description-proof`, `atproto`,
  `domain-control`, `domain-anchor`, `wallet-signature`, and a mutual `rel="me"`
  link (`rel-me`).
- **Claimed** (self-asserted, signed by the owner but not third-party confirmed):
  everything else.

Both tiers are covered by the signature; the tier describes how account control
was established, not whether the file is authentic. Note that `rel-me` is
Verified for display but is a URL-control proof, so it does not gate a scarce
handle (see 5).

## 4. Verification algorithm

Given a file, to verify (optionally against a trusted `expectedKeyId`):

1. Split the compact JWS and base64url-decode the payload segment. Parse it as
   JSON to read `subject.publicKey`. It MUST be `kty:"OKP"`, `crv:"Ed25519"`.
2. Verify the JWS signature (EdDSA) against that public key. On failure, reject.
3. Re-parse the manifest from the signature-verified bytes, so what you display
   can never diverge from what was signed.
4. Recompute `keyId` from `subject.publicKey` (section 2). It MUST equal
   `subject.keyId`. Otherwise reject.
5. If the caller supplied `expectedKeyId`, it MUST equal the recomputed `keyId`.
   Otherwise reject. **This is the real trust decision:** not "is there a file"
   but "is this signed by the key I already trust."

Pointer files verify the same way against their own payload.

## 4.1 Manifest history (sigchain)

Re-signing does not replace the past; each signed manifest is retained, so an
identity has an append-only history. Two signed fields make that history
tamper-evident:

- `seq`: 0 for the first manifest, then +1 each re-sign.
- `prev`: `base64url(SHA-256(previous manifest's compact JWS))`, or null at
  genesis.

Because `prev` is inside the signed payload, you cannot rewrite a past entry
without breaking every hash link and signature that follows it. To verify a whole
history (served oldest-first at
`https://realhandles.com/<user>/realhandles-chain.json`), check that each entry
verifies (section 4), `seq` starts at 0 and increments by 1, each `prev` equals
the hash of the previous entry's JWS, and the key is consistent. Missing
`seq`/`prev` on an older manifest is treated as genesis. This is `verifyChain` in
`@realhandles/verify`. Key rotation (a manifest whose key changes, authorized by
the previous key) is a planned extension.

## 5. Handle reservation

Short (scarce) handles cannot be grabbed first-come. Names of 8 characters or
fewer are PROTECTED and require a matching first-party-verified proof; names of 9
or more are open. Only proofs on curated key platforms or a controlled domain
qualify, and the shorter the name, the stronger the proof required: `.com` (100)
> an established strong TLD (80) > a tier-1 platform (60) > a tier-2 platform
(40). A throwaway or otherwise cheap TLD scores below the gating threshold, so it
adds to the trust score but cannot clear a scarce name (nobody grabs "ben" by
buying `ben.<cheap-tld>`). Claimed and URL-control proofs (including `rel-me`)
never gate a handle. The exact rules are in `@realhandles/verify`
(`evaluateClaim`, `tierFor`, `proofStrength`).

## 6. did:key

Every subject key is also a standard `did:key`: multicodec `ed25519-pub`
(`0xed 0x01`) prepended to the 32 raw public-key bytes, multibase base58btc
encoded with a `z` prefix. Deterministic, free, and interoperable with the
DID / verifiable-credentials ecosystem.

## 7. Conformance

The [`vectors/`](./vectors/) directory holds signed example files and their
expected verification results. A conforming verifier MUST accept the valid
vector and reject each invalid one for the stated reason.

## 8. Versioning

`version` and the schema `$id` are versioned together (`v1`). A breaking change
to the payload shape increments both. Verifiers should treat an unknown
`version` as unverifiable rather than guessing.
