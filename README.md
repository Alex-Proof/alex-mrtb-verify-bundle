# Independent Evidence Bundle Verifier

**Zuletzt bearbeitet:** 2026-09-06 (Sync -- war seit der RFC-3161-Kettenpruefung vom 05.09. hinter
dem echten Stand zurueck)
**Von:** MERIDIAN

Dieses Repository war seit dem 05.09.2026 nicht mehr synchron mit dem tatsaechlich verwendeten
Verifier -- `verify.ts` kannte weder die RFC-3161-Zertifikatsketten-Pruefung noch den unabhaengigen
Observer-Cross-Check, und `verify.py` fehlte hier komplett. Jetzt nachgezogen:

- **Proof Policies (Runtime Gate):** `evaluateProofPolicy()` prueft ein Bundle optional gegen eine
  Policy-Datei (`spec/policies/`, hier bewusst NICHT mitveroeffentlicht -- die einzige bestehende
  Beispiel-Policy haengt an einem internen, noch nicht produktiv verdrahteten Freigabe-Flow und
  wuerde ausserhalb dieses Kontexts nichts beweisen). CLI: `ALEX_VERIFY_POLICY_FILE=pfad node
  dist/verify.js bundle.json ...` -- blockiert mit Exit-Code 6, wenn eine Bedingung fehlt.
  `independent_witness` kann NUR erfuellt werden, wenn dieser Verifier selbst per
  `crossCheckObserverReceipt()` live gegen den Observer-Dienst geprueft hat -- nie eine blosse
  Behauptung aus dem Bundle.
- **Zwei echte Bugs behoben:** die Freigabe-Bindungspruefung (`approval_bundle_hash_mismatch`) und
  `verifyRfc3161Binding()` schlossen `observer_receipt` bisher nicht aus ihrer jeweiligen
  Nachrechnung aus, obwohl es serverseitig immer NACH Freigabe/Zeitstempel angehaengt wird -- jedes
  entsprechend bezeugte Bundle waere hier faelschlich als manipuliert abgelehnt worden.
- **`verify.py` neu:** der unabhaengige, netzlose Python-Verifier (Ed25519 ueber System-OpenSSL,
  keine Python-Pakete noetig) ist jetzt Teil dieses Repos, nicht nur der internen Kopie.
- **`spec/` neu:** die tatsaechlichen Invarianten (`INVARIANTS.md`), die eingefrorene
  `devtask.execution@1.0`-Spezifikation samt JSON-Schema, und das Kanonisierungs-Goldfile liegen
  jetzt hier -- vorher wurden sie nur in Code-Kommentaren referenziert, ohne dass eine externe
  Leserin sie tatsaechlich einsehen konnte.

`npm test` deckt weiterhin nur einen Teil ab: `verify.py` hat keine eigene Testsuite in diesem
Repo (identisch zur internen Kopie) und wird nur strukturell/durch manuellen Lauf geprueft.

---

**Zuletzt bearbeitet:** 2026-09-01
**Von:** MERIDIAN

`evidence-package@2.1` unterstuetzt: additive `customer_evidence`-Felder (Auftrag im Klartext,
Kosten-Teilerfassung, abgelehnte Aktionen, Freigabe-Objekt, deterministische lesbare
Zusammenfassung) plus ein zusaetzliches Pflichtfeld fuer jedes abgeschlossene Paket -- ein
signiertes `ci_result`, der echte GitHub-Check-Run-Ausgang des Ergebnis-Commits, nicht nur der
interne Kontroll-/Freigabepfad. Erstes oeffentliches Paket mit dieser Anforderung von Anfang an:
`evidence/pr-31-deepseek.json`, `prove-pr-31.sh` und `prove-pr-33.sh` fuehren die
Fremdverifikation End-zu-Ende vor. PR #33 ist der aktuelle, offen gelassene Inhaltsbeweis:

```bash
curl -O https://raw.githubusercontent.com/bewusstki-hue/alex-mrtb-verify-bundle/main/prove-pr-33.sh
bash prove-pr-33.sh
```

Das Skript prueft Signatur, Hash-Kette, Freigabe und den signierten Diff gegen den echten
GitHub-Diff. Ob die Aenderung den Auftrag fachlich erfuellt, bleibt eine Review-Entscheidung.

**Wichtig:** `evidence/pr-19-deepseek.json`, `pr-20-hermes.json` und `pr-21-cline.json` liefen VOR
Einfuehrung der `ci_result`-Pflicht und liefern mit diesem Verifier jetzt erwartungsgemaess
`required_evidence_mismatch` statt `VERIFIED` -- kein Zeichen von Manipulation, sondern eine
bewusste Verschaerfung der Anforderung selbst. Details: `evidence/README.md`.

---

**Zuletzt bearbeitet:** 2026-08-30
**Von:** MERIDIAN
Originale Evidence Packages der Engine-PRs #19-#21 liegen unter `evidence/`. Neue Pakete binden
Executor, Harness und Adapter-Version samt SHA-256 in den signierten Trace; historische V2-Pakete
ohne diese additiven Felder bleiben verifizierbar.

AI work should ship with evidence that can be checked without trusting the AI that produced it.

**Zuletzt bearbeitet:** 2026-08-26
**Von:** Codex (MERIDIAN)
V2 verlangt einen separat bezogenen Trust-Anchor und prüft Controller-Vollständigkeit.
R3/R4 erfordern zusätzlich eine gültige `sandbox-attestation@2.0` mit vier Manifest-/Policy-Hashes.

This repository contains a deterministic verifier for signed evidence bundles. It has no dependency
on the agent system that created a bundle.

## Try it in ten minutes

Requires Node.js 20 or newer.

```bash
npm install
npm test
npm run verify -- sample-bundle.json
npm run verify -- invalid-tampered-bundle.json
```

Evidence Package V2 benötigt zusätzlich den separat bezogenen Trust-Anchor:

```bash
npm run verify -- evidence-v2.json trusted-public-key.pem
```

Neue, freigegebene Pakete mit `approval_attestation_required: true` benoetigen zusaetzlich den
getrennten Approval-Anker:

```bash
npm run verify -- evidence-v2.json controller-key.pem approval-key.pem
```

Der im Paket mitgelieferte Schlüssel allein ist bei V2 ausdrücklich kein Vertrauensbeweis.

Den zu verwendenden Trust-Anchor bezieht man unabhängig von jedem einzelnen Bundle unter
`https://bewusstki.de/.well-known/alex-pubkey.json` (Felder `public_key_pem` und
`approval_signer.public_key_pem`) -- niemals aus dem
Bundle selbst. Dieser Endpunkt liefert das aktuell gültige, disk-persistente Ed25519-Schlüsselpaar
des Evidence-Signierdienstes; es überlebt Server-Neustarts (vor dem 29.08.2026 war das nicht der
Fall, siehe Changelog unten).

Expected results:

- the test suite passes;
- `sample-bundle.json` is accepted as `VERIFIED`;
- the deliberately altered bundle is rejected with exit code `2` and `invalid_signature`.

The verifier distinguishes three outcomes:

- `VERIFIED`: the supplied evidence satisfies the supported formal contract;
- `FAILED`: the supplied evidence contradicts that contract;
- `INCONCLUSIVE`: the available evidence is insufficient.

## What it verifies

- the cryptographic signature of the bundle payload;
- hash-chain integrity across raw `trace_events`;
- agreement between the declared outcome and the outcome derived from supported trace events;
- an outcome gate that accepts only `outcome="verified"` as successful.

Supported capability traces:

- `memory.provenance.attached@1.0` -> `memory_write:`
- `memory.delete.enforced@1.0` -> `memory_state_read:`
- `memory.tenant.isolation@1.0` -> `tenant_access_probe:`
- `memory.write.integrity@1.0` -> `memory_content_change:`
- `memory.audit.tamper_evident@1.0` -> `audit_chain_check:`
- `memory.recovery.verified@1.0` -> `memory_recovery:`
- `devtask.execution@1.0` -> `devtask_contract_bound:` / `devtask_attempt_started:` /
  `devtask_execution_context:` / `devtask_validation:` / `devtask_human_approval:` /
  `devtask_outcome:` (first non-`memory.*` capability: proves a real dev-task execution attempt
  ran under a specific frozen work contract, with which validation result, approved by whom, and
  with which final outcome). V2 verlangt zusätzlich Controller-Evidenz, vollständigen Diff-Hash,
  einen extern gelieferten Trust-Anchor und — bei R3/R4 — eine Sandbox-Attestierung. Fehlende
  Pflichtbelege ergeben `INCONCLUSIVE`; ältere V1-Bundles bleiben unverändert prüfbar.

## Exact computation rule (hash chain + signature payload)

Written out explicitly so this is reproducible without reading the TypeScript source:

**Hash chain.** For `trace_events = [e0, e1, ..., en]`:

```
prev = "genesis"
for each event e in trace_events (in order):
    hash = sha256(prev + e)     # plain UTF-8 string concatenation, no separator
    append hash to trace_hash_chain
    prev = hash
```

Each `trace_hash_chain[i]` is the hex-encoded SHA-256 digest. This is a linear hash chain (each
link depends on all prior events), not a Merkle tree.

**Signature payload.** The signed payload is the bundle object *minus* `signature` and
`public_key`, serialized with `JSON.stringify()` in exactly this key order:

```
V1: { bundle_id, capability, run_id, claim_ladder, executed_at, trace_events, trace_hash_chain, outcome }
V2: { schema_version, bundle_id, capability, run_id, claim_ladder, executed_at, trace_events,
      trace_hash_chain, outcome, signer_key_id, controller_evidence, required_evidence }
```

`signature` is the Ed25519 signature (Node `crypto.sign(null, Buffer.from(JSON.stringify(payload)), privateKey)`)
of that exact byte sequence, base64-encoded. `public_key` and `signature` are appended to the
bundle only after signing -- they are never part of what gets signed. Verification re-derives the
same payload object from the bundle (destructuring out `signature`/`public_key`), re-stringifies
it, and calls `crypto.verify()` against the embedded `public_key`.

This means: JSON key order matters for signature verification (JavaScript's `JSON.stringify`
preserves insertion order for string keys). A verifier in another language must reconstruct the
exact same key order, not just the same key/value pairs.

## Deliberate limits

This verifier proves formal integrity and consistency of the supplied bundle. It does not prove that
the external events described by the bundle happened in the real world.

For `memory.provenance.attached@1.0`, the current verifier checks agent identity and source hash.
Task-contract identity and timestamps are part of the provenance claim, but are not independently
attested by this verifier.

If one system controls both the work and every event in the bundle, an internally consistent bundle
can still contain false claims. Stronger assurance requires an independent event source, runtime
attestation, or reproducible re-execution.

## Why this exists

This began with a practical problem: AI-generated engineering work was moving faster than experienced
human review was available. The answer was not to demand more trust. It was to make claims portable,
make evidence inspectable, and let a separate deterministic tool say when the evidence is sufficient,
contradictory, or inconclusive.

`private: true` is intentional. This repository is public source, but the package is not currently
published to the npm registry and does not install a global command.

## License

Apache License 2.0. See [LICENSE](LICENSE).

**Last updated:** 2026-08-20

**By:** Codex (MERIDIAN)

Prepared the independent public release, negative example, and standalone regression tests.

---

**Last updated:** 2026-08-24

**By:** Claude Code (MERIDIAN)

Added `devtask.execution@1.0` support, mirrored line-for-line from `server/services/mrtb/evidenceBundle.server.ts` (still a deliberate separate code copy, no shared import between server and standalone verifier). Own regression suite (`npm test`) still green, existing sample/tampered bundles still verify unchanged.

---

**Last updated:** 2026-08-25

**By:** Claude Code (MERIDIAN)

Following external review feedback on a real published `devtask.execution@1.0` bundle: added the exact hash-chain/signature-payload computation rule as prose (reproducible without reading the TS source), and optional `devtask_diff_evidence` parsing (SHA-256 of the `diff_stat` summary line -- not the full diff, informational only, does not change derived outcome). Server-side change mirrored in `server/services/mrtb/evidenceBundle.server.ts` + `server/services/alexWorkflowCore.server.ts`, typecheck clean.
**Zuletzt bearbeitet:** 2026-08-27
**Von:** Codex (MERIDIAN)
Der unabhaengige Verifier prueft `repository-state@1.0`: Vorher-/Nachher-Baum,
Ergebnis-Commit und SHA-256-Inhaltshashes jeder geaenderten Datei.

**Zuletzt bearbeitet:** 2026-08-27
**Von:** Codex (MERIDIAN)
Optionaler L3-Pfad: separat signierte `validation-attestation@1.0` aus einem digest-gepinnten,
netzlosen Runner plus `reviewer-attestation@1.0`, die exakte Bundle-/Validation-Bytes bindet.

**Zuletzt bearbeitet:** 2026-08-29
**Von:** Claude Code (MERIDIAN)
Externer Vertrauensanker ergänzt: `https://bewusstki.de/.well-known/alex-pubkey.json` liefert das
Ed25519-Schlüsselpaar unabhängig vom Bundle. Voraussetzung dafür live gefunden und gefixt:
`ensureKeypair()` nutzte den RAM-only-Pfad des Server-Keystores, jeder Prozessneustart erzeugte
ein neues Schlüsselpaar -- ein extern verteilter Schlüssel wäre spätestens beim nächsten Deploy
wertlos gewesen. Jetzt disk-persistent (`server/services/mrtb/evidenceBundle.server.ts`).

**Zuletzt bearbeitet:** 2026-08-29 (Nachtrag, gleicher Tag)
**Von:** Claude Code (MERIDIAN)
Optionales `rfc3161_timestamp`-Feld ergänzt (`Rfc3161Timestamp`-Interface,
`verifyRfc3161Binding()`) -- bestätigt, dass ein von einer öffentlichen Zeitstempelstelle
(FreeTSA) angehefteter RFC-3161-Zeitstempel wirklich zum vorliegenden Bundle-Inhalt gehört.
`verifyBundleObject()` schließt das Feld korrekt aus der signierten Nutzlast aus (es wird immer
erst NACH dem Signieren angehängt). Geprüft wird ausdrücklich nur die Hash-Bindung, nicht die
CMS-Signatur der TSA selbst oder deren Zertifikatskette -- das rohe `token_der_base64` ist
Standard-RFC-3161-DER und mit externen Werkzeugen (z.B. `openssl ts`) unabhängig prüfbar.

Ehrlicher Stand der Claim-Ladder, da das Typ-System `"L0"|"L1"|"L2"|"L3"|"L4"` mehr suggeriert als
der Server tatsächlich vergibt: `createSignedEvidenceBundleV2()` erzeugt ausschließlich `L0`
(nicht verifiziert) oder `L2` (verifiziert). `L3` existiert nur als optionaler, separater Pfad
außerhalb des Bundle-Felds selbst (siehe Eintrag oben, 27.08.) -- das `claim_ladder`-Feld im
Bundle bleibt dabei bei `L2`, nur eine zusätzliche, separat geprüfte Attestierung kommt hinzu.
`L1` und `L4` sind reine Typ-Slots ohne Erzeugungslogik. Kein `L5` im Typ vorhanden (Vorschlag aus
einer externen Härtungs-Review, noch nicht umgesetzt: unabhängige Event-Quelle oder Hardware-
Attestierung, siehe "Deliberate limits" oben).

**Zuletzt bearbeitet:** 2026-08-30
**Von:** Codex (MERIDIAN)
Neue freigegebene V2-Pakete tragen eine zweite Ed25519-Signatur ueber den SHA-256 des exakten,
bereits signierten Bundles. Das signierte Pflichtmerkmal verhindert stilles Weglassen;
historische V2-Pakete bleiben unveraendert gueltig und werden nicht nachsigniert.
