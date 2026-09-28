# Trust Boundary — Signing Identity and Key Lifecycle

**Status:** current, 2026-09-29. Written in response to a direct question from an external reviewer
(Iman Schrock, EMILIA-Protocol) about what identity this verifier actually pins, how that differs
from the server that happens to serve it, and what a key change means for bundles signed before it.

## What the verifier trusts

The verifier trusts exactly one thing: an Ed25519 **public key**, supplied out of band by the
caller (a local PEM file, or fetched independently from
`https://bewusstki.de/.well-known/alex-pubkey.json` — never taken from the bundle itself, see
README). There is no separate **Issuer identity** — no DID, no registered entity, no
organizational identity distinct from the bare key. The `purpose` field on a key
(`evidence_package` or `human_approval`) is a role label, not an issuer identity. If you verify a
bundle, the party you are trusting is "whoever holds this specific private key," full stop.

This is also the answer to "server vs. signer": the server at `bewusstki.de` serves the current
public key and the bundle JSON, but it is not itself the trust anchor — the trust anchor is the key
material, checked by signature, independent of which server happened to deliver the bytes.

## Key rotation and revocation

`rotateEvidenceSigningKey()` / `rotateApprovalSigningKey()` (`core/mrtb/evidenceBundle.server.ts`,
private repo) require an explicit confirmation string and a stated reason (min. 12 characters).
Rotation does not delete the old key — it appends a record to a persisted revocation history:

```
{ key_id, public_key_pem, valid_from, revoked_at, reason, replaced_by }
```

This full history, including the historical public key PEMs (not just their hashes), is published
in the `revocations` array of the same `/.well-known/alex-pubkey.json` endpoint, alongside the
currently active keys. Old keys are not erased from the public record when replaced.

## What an old bundle means after a key change

The registry states its own policy explicitly: `historical_bundle_verification:
"requires_archived_key_from_bundle_issuance_period"`. In other words: by design, a bundle should be
checked against the key that was active when it was issued, not against whatever key is active now.

**What is and isn't automated:** `verifyBundleObject()` (`tools/verify-bundle/verify.ts` /
`verify.py`) accepts exactly one `trustedPublicKey` per invocation and checks the bundle's embedded
`public_key` against it. There is no code path that automatically selects the correct historical
key from `revocations` based on a bundle's `executed_at` timestamp or `signer_key_id`. After a
rotation, verifying an older bundle is a **manual** step: look up the matching entry in
`revocations` by `key_id`, extract its `public_key_pem`, and pass that PEM explicitly. A bundle
signed under a revoked key will not verify against the current key, and nothing in this repository
currently automates the fallback.

## Deliberate limits (unchanged from the rest of this repo's stance)

This describes what the mechanism does, not a claim that it needs no further work. Two concrete,
honestly-named gaps: (1) no separate Issuer-identity abstraction beyond the raw key; (2) no
automated historical-key resolution in the verifier itself. Both are real, both are open, neither
is hidden.
