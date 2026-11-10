#!/usr/bin/env bash
# Verify that a release tarball of this repo was really built by THIS repo's GitHub Actions
# workflow (.github/workflows/release.yml), on a tag, not hand-crafted and uploaded by someone
# with push access to the GitHub release. Needs: cosign (https://docs.sigstore.dev/cosign/installation).
#
# Usage: ./verify-release.sh <tarball> <tarball>.sig <tarball>.pem
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <tarball> <signature> <certificate>" >&2
  exit 1
fi

tarball="$1"
signature="$2"
certificate="$3"

exec cosign verify-blob \
  --certificate "$certificate" \
  --signature "$signature" \
  --certificate-identity-regexp '^https://github\.com/Alex-Proof/alex-mrtb-verify-bundle/\.github/workflows/release\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$tarball"
