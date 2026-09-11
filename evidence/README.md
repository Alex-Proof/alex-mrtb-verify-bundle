# Public engine-run evidence

**Zuletzt bearbeitet:** 2026-09-01
**Von:** MERIDIAN

Diese Dateien sind die unveraenderten, signierten Evidence Packages von PRs im oeffentlichen
Demo-Repository:

- `pr-19-deepseek.json` — DeepSeek
- `pr-20-hermes.json` — Hermes
- `pr-21-cline.json` — Cline
- `pr-31-deepseek.json` — DeepSeek, erstes Paket im Schema `evidence-package@2.1` mit einem
  echten `ci_result` (GitHub-Check-Runs live abgefragt, nicht nur behauptet)

## Wichtiger Unterschied: `pr-19`/`pr-20`/`pr-21` vs. `pr-31`

`verify.ts` verlangt seit dieser Aktualisierung fuer jedes abgeschlossene `devtask.execution`-Paket
zusaetzlich ein signiertes `ci_result` (der tatsaechliche GitHub-Check-Run-Ausgang des Ergebnis-
Commits, nicht nur der interne Kontroll-/Freigabepfad). `pr-19`, `pr-20` und `pr-21` liefen VOR
Einfuehrung dieser Pruefung und enthalten das Feld nicht — der Verifier lehnt sie deshalb jetzt mit
`required_evidence_mismatch` ab, nicht weil an den Paketen etwas manipuliert wurde, sondern weil die
Anforderung selbst strenger geworden ist. `pr-31` ist das erste oeffentliche Paket, das diese
Anforderung von Anfang an erfuellt und vollstaendig `VERIFIED` durchlaeuft.

Sie wurden ausserdem vor Einfuehrung der maschinenlesbaren Executor-Bindung erzeugt. Die Engine-
Zuordnung stammt deshalb bei diesen historischen Paketen aus dem jeweiligen Task-/PR-Datensatz und
ist noch nicht Teil des signierten Trace. Neuere Pakete (ab `pr-31`) enthalten `executor`,
`harness_id`, `adapter_version` und `adapter_version_sha256` im `devtask_execution_context`-Event.

## Fremdverifikation aus einem frischen Clone

```bash
git clone https://github.com/Alex-Proof/alex-mrtb-verify-bundle.git
cd alex-mrtb-verify-bundle
npm ci
npm run build
curl -fsS https://bewusstki.de/.well-known/alex-pubkey.json \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.parse(s).public_key_pem))' \
  > trusted-public-key.pem
node dist/verify.js evidence/pr-31-deepseek.json trusted-public-key.pem
```

Erwartung: `VERIFIED`. Der Trust-Anchor kommt bewusst aus dem Well-known-Endpunkt, nicht aus dem
jeweiligen Bundle. `pr-19`/`pr-20`/`pr-21` liefern mit demselben Aufruf erwartungsgemaess
`required_evidence_mismatch` (siehe Abschnitt oben).
