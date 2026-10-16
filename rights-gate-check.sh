#!/usr/bin/env bash
# rights-gate-check.sh -- fragt den LIVE Policy Kernel von ALEX, was er fuer einen geplanten
# Auftrag erlauben oder verweigern wuerde, BEVOR der Auftrag laeuft.
#
# Wichtiger Unterschied zu verify.ts/verify.py oben: das hier ist KEIN unabhaengiger Beweis.
# Dieses Skript vertraut dem Server unter alexproof.de fuer die Dauer der Anfrage -- es
# verifiziert keine Signatur und prueft kein bereits ausgestelltes Evidence Package, sondern
# stellt eine Frage an das aktuell laufende System und gibt dessen Antwort unveraendert zurueck.
# Nutze es, um einen geplanten Auftrag VOR dem echten Lauf gegenzuchecken -- nicht als Nachweis
# fuer einen bereits erfolgten Lauf (dafuer sind verify.ts/verify.py da).
#
# Die Server-Route (host/routes/rightsGateCheck.ts, privates alex-core-Repo) ruft denselben
# Policy-Kernel-Code auf wie der echte Kundenpfad, erzeugt pro Anfrage ein frisches, leeres
# Temp-Verzeichnis als Arbeits-Root (wird direkt danach geloescht) und fuehrt selbst nie einen
# Effekt aus. fs_path-Ziele im Plan muessen deshalb RELATIV sein (z.B. "src/index.ts"), nicht
# absolut gegen eine dir bekannte Root -- die Root existiert nur fuer die Dauer dieser einen Anfrage.
#
# Benutzung:
#   bash rights-gate-check.sh plan.json
#   bash rights-gate-check.sh sample-rights-gate-plan.json   (Beispiel-Plan in diesem Repo)
#
# Plan-Format (JSON):
#   { "auftragId": "...", "allowedWritePaths": ["."], "plannedCalls": [
#       { "tool": "write_file", "params": { "path": "src/index.ts" } } ] }
#
# Voraussetzungen: bash, curl, node (nur zum Pretty-Print der Antwort, keine Pakete noetig).
set -euo pipefail

PLAN_FILE="${1:-}"
if [ -z "$PLAN_FILE" ] || [ ! -f "$PLAN_FILE" ]; then
  echo "Benutzung: $0 <plan.json>" >&2
  echo "Beispiel:  $0 sample-rights-gate-plan.json" >&2
  exit 1
fi

ENDPOINT="https://alexproof.de/api/rights-gate-check"
echo "== Frage den live Policy Kernel unter $ENDPOINT =="
RESPONSE="$(curl -sS -X POST "$ENDPOINT" -H 'Content-Type: application/json' --data-binary "@$PLAN_FILE")"

echo "$RESPONSE" | node -e '
let input = "";
process.stdin.on("data", d => { input += d; });
process.stdin.on("end", () => {
  const result = JSON.parse(input);
  if (result.error) {
    console.error("Fehler vom Server:", result.error, result.message || "");
    process.exit(1);
  }
  console.log("");
  console.log("Auftrag:", result.auftragId);
  for (const call of result.calls) {
    const mark = call.decision === "allow" ? "ALLOW" : "DENY ";
    console.log(`  [${mark}] ${call.tool}  (${call.reason})`);
  }
  console.log("");
  console.log("Blockierte Versuche:", result.blockedAttempts.length);
  console.log("Persistenz-Beobachtung:", result.persistenceObservation.note);
});
'
