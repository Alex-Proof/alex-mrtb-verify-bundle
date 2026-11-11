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
# Needs: cosign (https://docs.sigstore.dev/cosign/installation) and gh
# (https://cli.github.com/, logged in or just unauthenticated public access is enough).
#
# Usage: ./verify-release.sh <tarball> <tarball>.sig <tarball>.pem
set -euo pipefail

REPO="Alex-Proof/alex-mrtb-verify-bundle"

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <tarball> <signature> <certificate>" >&2
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
