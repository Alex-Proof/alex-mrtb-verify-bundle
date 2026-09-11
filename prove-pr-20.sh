#!/usr/bin/env bash
# Beweist zwei unabhaengige Dinge zu PR #20 von alex-controlled-agent-demo,
# ohne ALEX oder Bewusst.Ki zu vertrauen -- nur oeffentliche Quellen (GitHub, bewusstki.de/.well-known):
#
#   L1: Signatur + Hash-Kette des Evidence Package stimmen mit dem aktuellen Well-known-Key ueberein.
#   L2: Der im Paket signierte Diff ist Byte-fuer-Byte derselbe Diff, den GitHub fuer dieselben
#       zwei Commits liefert -- nicht nur "steht im JSON", sondern gegen Git nachgerechnet.
#
# Voraussetzungen: bash, curl, git, Node.js >= 20 (https://nodejs.org). Sonst nichts.
set -euo pipefail

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

echo "== [1/4] Verifier-Quelle klonen und bauen (kein vorgefertigtes Binary) =="
git clone --quiet https://github.com/Alex-Proof/alex-mrtb-verify-bundle.git verifier
(cd verifier && npm install --silent && npm run build --silent)

echo "== [2/4] Beweispaket + aktuellen Trust-Anchor laden =="
curl -sO https://bewusstki.de/downloads/verify-bundle/demo-pr-20.json
curl -s https://bewusstki.de/.well-known/alex-pubkey.json -o pubkey.json
node -e "process.stdout.write(require('./pubkey.json').public_key_pem)" > trusted-public-key.pem

echo "== [3/4] L1 -- Signatur + Hash-Kette gegen den Well-known-Key pruefen =="
node verifier/dist/verify.js demo-pr-20.json trusted-public-key.pem

echo "== [4/4] L2 -- Diff im Paket gegen den echten Diff auf GitHub nachrechnen =="
BASE=$(node -e "console.log(require('./demo-pr-20.json').controller_evidence.repository_state.base_commit)")
RESULT=$(node -e "console.log(require('./demo-pr-20.json').controller_evidence.repository_state.result_commit)")
git clone --quiet https://github.com/Alex-Proof/alex-controlled-agent-demo.git repo
git -C repo diff "$BASE" "$RESULT" > github_diff.txt

node -e "
const fs = require('fs');
const crypto = require('crypto');
const bundle = require('./demo-pr-20.json');
// git diff haengt am Ende einen Zeilenumbruch an, das Paket speichert den Diff getrimmt --
// das ist der einzige Unterschied, sonst identischer Bytestrom.
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
echo "Fertig. PR ansehen: https://github.com/Alex-Proof/alex-controlled-agent-demo/pull/20"
