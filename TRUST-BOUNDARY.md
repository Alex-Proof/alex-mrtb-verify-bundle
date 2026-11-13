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

## What a release does NOT prove (branch protection, cooldown, and the limits of CI self-attestation)

**Status:** current, 2026-11-13. Written in response to a direct question from an external
reviewer (Bluesky) on the `critical-file-cooldown` workflow: "Enforced even for you is the honest
part, but protection and the cooldown are live GitHub state, not evidence: a digest built in a
window when the rules were off verifies exactly like one built with them on. Is that rule state
attested at build time? Otherwise the chain proves the commit existed, not that it was produced
under protection. And 24h buys visibility, not a second pair of eyes."

That question was correct, and here is the direct answer.

**What changed:** every tagged release now ships a `*.protection-snapshot.json` file, signed with
the same cosign/GitHub-OIDC flow as the release tarball (its own signature, not folded into the
tarball's). It records, as the GitHub API reports it at the moment the release workflow runs:
`enforce_admins`, `required_signatures.enabled`, the full `required_status_checks` context list
(including `critical-file-cooldown` once it is wired in as a required check), and the required
approving-review count on `main`. It is built by the same release job, with the same
`GITHUB_TOKEN`, as everything else in the release — there is no second, independent party
producing it.

**What this does NOT prove, stated plainly:**

- **It is a snapshot, not a history.** It attests to the protection state at the moment the
  release tag was built — not the state that was active while the commits being released were
  *written*. A window with protection briefly disabled, followed by a release built after it was
  re-enabled, produces a snapshot that looks identical to one where protection was never touched.
  Closing that gap needs either a continuously-recorded protection-change audit log cross-checked
  against every commit's authorship window, or an attestor outside this repository's own control —
  neither exists here.
- **The 24-hour cooldown (`critical-file-cooldown.yml`) buys public visibility, not a second
  reviewer.** It guarantees a security-critical change sat in the open for a day before it could
  merge. It does not guarantee that anyone looked, and it is not a substitute for
  `required_pull_request_reviews` with a real second maintainer (this repository's
  `required_approving_review_count` is `0` — see the snapshot's own field for the current value,
  not this sentence, since it can change).
- **This CI cannot attest to its own integrity.** The snapshot, the signature, and the workflow
  that produces both run under the same GitHub account that also writes the code they describe.
  A party that could tamper with this repository's Actions configuration could, in principle, also
  tamper with the step that reports "protection was on." Real independence from that failure mode
  requires a verifier outside this repository's control — this snapshot is not that, and does not
  claim to be.

None of the above is new work this change does *not* also need — it is the honest boundary of what
build-time rule-state attestation can mean when the attestor and the thing being attested share an
owner. See also the top of this document for the equivalent limit on signing-key trust.
