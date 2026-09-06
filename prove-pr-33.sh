#!/usr/bin/env bash
# Beweist zwei unabhaengige Dinge zu PR #33 von alex-controlled-agent-demo,
# ohne ALEX oder Bewusst.Ki zu vertrauen -- nur oeffentliche Quellen (GitHub, bewusstki.de/.well-known):
#
#   L1: Signatur + Hash-Kette des Evidence Package stimmen mit den aktuellen Well-known-Keys
#       ueberein; Freigabe und CI-Ergebnis sind Bestandteil des signierten Pakets.
#   L2: Der im Paket signierte Diff ist Byte-fuer-Byte derselbe Diff, den GitHub fuer dieselben
#       zwei Commits liefert -- nicht nur "steht im JSON", sondern gegen Git nachgerechnet.
#
# Das Skript beweist nicht, dass die Aenderung fachlich richtig ist. Das entscheidet die Review
# gegen Auftrag und Abnahmekriterien. Es erzeugt auch keine gesetzliche Echtheitsvermutung.
#
# Voraussetzungen: bash, curl, git, Node.js >= 20 (https://nodejs.org). Sonst nichts.
set -euo pipefail

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

echo "== [1/4] Verifier-Quelle klonen und bauen (kein vorgefertigtes Binary) =="
git clone --quiet https://github.com/Alex-Proof/alex-mrtb-verify-bundle.git verifier
(cd verifier && npm install --silent && npm run build --silent)

echo "== [2/4] Beweispaket + aktuelle Trust-Anchor laden =="
curl -sO https://bewusstki.de/downloads/verify-bundle/demo-pr-33.json
curl -s https://bewusstki.de/.well-known/alex-pubkey.json -o pubkey.json
node -e "process.stdout.write(require('./pubkey.json').public_key_pem)" > trusted-public-key.pem
node -e "process.stdout.write(require('./pubkey.json').approval_signer.public_key_pem)" > trusted-approval-key.pem

# PR #33 wurde mit inzwischen abgeloesten Schluesseln signiert (Details:
# https://bewusstki.de/evidence-key-rotation.html) -- die aktuellen Well-known-Keys passen
# dann nicht mehr. Historische Schluessel (Evidence UND Freigabe getrennt) aus derselben
# Antwort nachschlagen, falls noetig.
node -e "
const pubkey = require('./pubkey.json');
const bundle = require('./demo-pr-33.json');
const revocations = (pubkey.trust_anchor_registry && pubkey.trust_anchor_registry.revocations) || [];
function resolve(keyId, activeId, activePem, outFile, label) {
  if (keyId === activeId) return;
  const match = revocations.find(r => r.key_id === keyId);
  if (!match) { console.error('Kein aktiver oder historischer ' + label + '-Schluessel fuer ' + keyId + ' gefunden.'); process.exit(1); }
  require('fs').writeFileSync(outFile, match.public_key_pem);
  console.log('Hinweis: PR #33 nutzt einen abgeloesten ' + label + '-Schluessel (' + match.key_id + '), historischen Wert verwendet.');
}
resolve(bundle.signer_key_id, pubkey.key_id, pubkey.public_key_pem, 'trusted-public-key.pem', 'Evidence');
if (bundle.approval_attestation) resolve(bundle.approval_attestation.signer_key_id, pubkey.approval_signer.key_id, pubkey.approval_signer.public_key_pem, 'trusted-approval-key.pem', 'Freigabe');
"

echo "== [3/4] L1 -- Signatur + Hash-Kette + ci_result + Freigabe-Attestation pruefen =="
node verifier/dist/verify.js demo-pr-33.json trusted-public-key.pem trusted-approval-key.pem

echo "== [4/4] L2 -- Diff im Paket gegen den echten Diff auf GitHub nachrechnen =="
BASE=$(node -e "console.log(require('./demo-pr-33.json').controller_evidence.repository_state.base_commit)")
RESULT=$(node -e "console.log(require('./demo-pr-33.json').controller_evidence.repository_state.result_commit)")
git clone --quiet https://github.com/Alex-Proof/alex-controlled-agent-demo.git repo
git -C repo diff "$BASE" "$RESULT" > github_diff.txt

node -e "
const fs = require('fs');
const crypto = require('crypto');
const bundle = require('./demo-pr-33.json');
// git diff haengt am Ende einen Zeilenumbruch an, das Paket speichert den Diff getrimmt.
const githubDiff = fs.readFileSync('github_diff.txt', 'utf8').replace(/\n\$/, '');
const actual = crypto.createHash('sha256').update(githubDiff).digest('hex');
const expected = bundle.controller_evidence.diff_full_sha256;
console.log('erwartet (aus dem signierten Paket): ' + expected);
console.log('gerechnet (aus dem echten GitHub-Diff): ' + actual);
if (actual !== expected) {
  console.error('L2 FEHLGESCHLAGEN -- der Diff im Paket weicht vom Diff auf GitHub ab.');
  process.exit(1);
}
console.log('');
console.log('L2 BESTAETIGT: der im Paket signierte Diff ist exakt der Diff, den GitHub');
console.log('fuer ' + '$BASE'.slice(0,12) + '..' + '$RESULT'.slice(0,12) + ' zeigt.');
"

echo ""
echo "Fertig. Fachliche Richtigkeit bleibt eine Review-Entscheidung."
echo "PR ansehen: https://github.com/Alex-Proof/alex-controlled-agent-demo/pull/33"
