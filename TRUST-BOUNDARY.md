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

## The release-tag signing key (a separate trust domain from the Evidence/Approval keys above)

**Status:** current, 2026-11-16. Written in response to a direct question from an external
reviewer (Bluesky) following the cosign/OIDC and `allowed_signers` work: does this key live
outside GitHub Actions, and what rotates or revokes it?

This key is unrelated to the Ed25519 Evidence/Approval keys documented above. It is the SSH key
`git verify-tag` checks a release tag's signature against (`.github/allowed_signers`,
`git config gpg.ssh.allowedSignersFile`, enforced in `release.yml` before the build/package job
runs). Today there is exactly one entry, one SSH key, held by the repository's sole maintainer.

**Custody — confirmed by reading the workflow, not asserted:** `release.yml` contains no
`secrets.*` reference anywhere. The private key is never uploaded as a repository/organization
secret and is not reachable by any Actions runner. Tags are signed locally, before the signed tag
is pushed; CI only verifies (`git verify-tag`), it never signs. A compromised `release.yml` could
at most forge a build around an already-valid tag — it cannot mint a new valid tag signature,
because the signing key never enters the CI environment.

**Rotation/revocation — reuses existing machinery, not a new one:** `.github/allowed_signers`
is itself a file in this repository, and `main` already requires `required_signatures: true` and
`enforce_admins: true` (no bypass, including for the maintainer). Replacing or adding a key means
editing this file through a signed commit on a reviewed PR — the same path, and the same
guarantees, as any other change to this repository. PR #17 (merged 2026-11-16) adds a 24-hour
public-cooldown requirement specifically for this file (and for `verify.ts`/`verify.py`/
`release.yml`/`trust-anchor.json`) before it can merge, and it is now wired in as a required
status context in branch protection — a rotation needs both a signed commit and 24h of public
visibility first. There is no separate witnessed-registry/append-only-log construction for this
key, unlike the Evidence/Approval key revocations above — it was judged unnecessary here because
the control already in place (signed-commit-only, no admin bypass, cooldown, on a single-
maintainer repo) is the actual bottleneck, and a second logging layer around it would not change
who can authorize a change, only how visibly they did it.

**What this does not cover:** if the maintainer's own SSH key or GitHub account is compromised,
this entire boundary collapses — same single-point-of-trust limit as the rest of this repo's
model (see the top of this document). Nothing here claims otherwise.

## allowed_signers was its own trust root (fixed 2026-11-17)

**Status:** current, 2026-11-17. Written in response to a direct follow-up from the same external
reviewer (Bluesky): `allowed_signers` had the same root as the tags it authorizes — the one key in
that file both defines trust and signs the releases that trust approves. A stolen key could add a
second line to the file and sign the commit that added it, and `required_signatures` would pass,
because it only checks "is this commit signed by *a* key in `allowed_signers`," not "is this the
*right* `allowed_signers`." Nothing pinned the file's content from outside the repo's own commit
history.

**What changed:** `release.yml` now has a step, run before `git verify-tag`, that hashes
`.github/allowed_signers` and compares it against a GitHub Actions secret
(`ALLOWED_SIGNERS_SHA256`). A mismatch fails the release hard, before the signature check ever
runs. The secret is not a second signing key — it is a pinned expected value, checked by string
equality, nothing cryptographic beyond the hash itself.

**Why a secret and not a second SSH key:** a second key sounds like real separation of duty, but on
a single-maintainer repo both keys end up held by the same person, usually on the same machine —
compromising one plausibly compromises both, so it buys little. A GitHub Actions secret sits behind
a different access boundary: reading or changing it needs GitHub account/API access, not possession
of the SSH signing key. A stolen signing key alone can still forge a signed commit that rewrites
`allowed_signers`, and can still get `critical-file-cooldown` to pass after 24h of nobody noticing —
but it cannot make that forged file match the pinned hash, because the secret isn't derived from, or
reachable by, that key.

**What this does not cover, stated plainly:** if the GitHub account itself is compromised (not just
the SSH key), the attacker can update `ALLOWED_SIGNERS_SHA256` to match their forged file and this
check passes trivially — same single-point-of-trust limit as everywhere else in this document, just
moved from "steal one SSH key" to "steal the GitHub account." It also means every legitimate key
rotation now needs a manual, out-of-band secret update in addition to the signed-commit-plus-
cooldown path above; skipping that step after a real rotation breaks releases until the secret is
updated, it does not silently fall back to trusting the file unpinned.
