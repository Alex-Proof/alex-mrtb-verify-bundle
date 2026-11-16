#!/usr/bin/env bash
# Verify a release tarball of this repo two ways, not one:
#
#   1. cosign verify-blob  -- proves SOME run of this repo's release.yml, on a tag, signed this
#      exact file. This binds to the WORKFLOW's identity, not to a specific source commit: a
#      compromised release.yml still signs, cleanly and verifiably, whatever it is told to build.
#   2. gh attestation verify -- proves the SLSA build provenance attestation for this exact
#      artifact digest, recording which source commit and build recipe produced it. This is the
#      check that binds the digest to the commit, closing the gap step 1 leaves open.
#
# Optionally, pass the release's *.protection-snapshot.json + its .sig/.pem as three more
# arguments to also check the build-time branch-protection attestation (see TRUST-BOUNDARY.md,
# "What a release does NOT prove"). This only checks the signature and prints the recorded
# values -- it cannot and does not prove the rules held for the whole commit history, or that
# this CI's own report of itself is honest. Treat a clean result here as "nothing is hidden",
# not as "independently confirmed".
#
# Needs: cosign (https://docs.sigstore.dev/cosign/installation) and gh
# (https://cli.github.com/, logged in or just unauthenticated public access is enough).
#
# Usage: ./verify-release.sh <tarball> <tarball>.sig <tarball>.pem [snapshot.json snapshot.sig snapshot.pem]
set -euo pipefail

REPO="Alex-Proof/alex-mrtb-verify-bundle"

if [ "$#" -ne 3 ] && [ "$#" -ne 6 ]; then
  echo "Usage: $0 <tarball> <signature> <certificate> [snapshot.json snapshot.sig snapshot.pem]" >&2
  exit 1
fi

tarball="$1"
signature="$2"
certificate="$3"

echo "== [1/2] cosign verify-blob -- signed by this repo's release workflow, on a tag =="
cosign verify-blob \
  --certificate "$certificate" \
  --signature "$signature" \
  --certificate-identity-regexp "^https://github\\.com/${REPO}/\\.github/workflows/release\\.yml@refs/tags/.*\$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$tarball"

echo "== [2/2] gh attestation verify -- SLSA provenance binds this digest to its source commit =="
gh attestation verify "$tarball" --repo "$REPO"

echo "Both checks passed: signed by this repo's release workflow, AND this digest's provenance traces to a specific source commit and build recipe."

if [ "$#" -eq 6 ]; then
  snapshot="$4"
  snapshot_sig="$5"
  snapshot_cert="$6"

  echo ""
  echo "== [optional] branch-protection snapshot -- build-time state, signed by the same workflow =="
  cosign verify-blob \
    --certificate "$snapshot_cert" \
    --signature "$snapshot_sig" \
    --certificate-identity-regexp "^https://github\\.com/${REPO}/\\.github/workflows/release\\.yml@refs/tags/.*\$" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$snapshot"

  echo "Signature OK. Recorded values (this repo's CI reporting on itself -- not an independent party):"
  cat "$snapshot"
  echo ""
  echo "This does NOT prove the rules held for the commits in this release, only that the GitHub"
  echo "API reported these values at the moment release.yml ran. See TRUST-BOUNDARY.md."
fi
