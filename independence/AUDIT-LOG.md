# Audit Log — Independence Test Kit

Format mirrors the external auditor's own discipline that produced finding INDEP-001: every
verdict pinned to a commit and a toolchain, recorded as PASS, FAIL or UNRESOLVED, never a bare
"fixed".

## INDEP-001 — Frozen manifest referenced live, moving files

- **Reported by:** Matthew (EFMW Zoo / Monolithic), 2026-11-19, replaying the documented offline
  procedure for `demo-pr-38.json` with Python 3.12.14 and OpenSSL 3.5.7.
- **Verdict at `c8f4fd2` (repo HEAD at report time):** UNRESOLVED.
  `sha256sum -c independence/SHA256SUMS` — 7/9 `OK`, `verify.py` and
  `spec/devtask.execution@1.0.schema.json` `FAILED`.
- **Verdict at `b3d1148` (the frozen source state `independence/README.md` names as tested):**
  PASS. All 9 files `OK`; `python3 verify.py independence/demo-pr-38.json ...` → `VERIFIED`.
  Confirmed independently by the reporter and reproduced here.
- **Root cause:** `independence/SHA256SUMS` and `independence/README.md` pointed at the live,
  tracked `../verify.py` and `../spec/` instead of a self-contained copy. Both files legitimately
  changed after the kit's 2026-09-06 freeze — `spec/devtask.execution@1.0.schema.json` on
  2026-09-28 (new required `epistemic_gate` field), `verify.py` on 2026-11-15 (A-016, independent
  WebAuthn approval check). No divergence, no tampering, at `b3d1148` itself.
- **Fix:** [PR #34](https://github.com/Alex-Proof/alex-mrtb-verify-bundle/pull/34), merged as
  `a9578b3` into `main` on 2026-11-19. `verify.py` and `spec/` snapshotted into `independence/` at
  the `b3d1148` state; `SHA256SUMS` and `README.md` repointed to the snapshot copies so the kit no
  longer drifts when the live verifier picks up further, legitimate security fixes.
- **Verdict at `a9578b3` (post-fix, fresh clone of `main`):** PASS.
  `sha256sum -c independence/SHA256SUMS` — 9/9 `OK`; `python3 independence/verify.py
  independence/demo-pr-38.json independence/trusted-evidence.pem independence/trusted-approval.pem`
  → `VERIFIED`.
- **Independently reproducible:**
  ```bash
  git clone https://github.com/Alex-Proof/alex-mrtb-verify-bundle
  cd alex-mrtb-verify-bundle
  sha256sum -c independence/SHA256SUMS
  python3 independence/verify.py independence/demo-pr-38.json \
    independence/trusted-evidence.pem independence/trusted-approval.pem
  ```
- **What this does NOT claim:** that the independence kit is now immune to drift forever — a
  future change to the snapshot copies themselves, or to `demo-pr-38.json`/the trust anchor, would
  need the same scrutiny. This entry closes INDEP-001 only.
