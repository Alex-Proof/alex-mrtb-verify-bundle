# webauthn-approval-assertion@1.0

Status: Spec vor dem ersten Code (spec-first-gate, Einstufung "Gross", bestaetigt durch Andre
15.11.2026). Massstab: `INVARIANTS.md`. Fortsetzung von A-016 (`docs/ASSUMPTIONS.md`, alex-core;
alex-core-Teil dort bereits CONFIRMED).

## Ziel

`controller_evidence.webauthn_approval_assertion` (Typ `WebauthnApprovalAssertionV1`, additiv,
seit A-016 vom alex-core-Produzenten befuellt) liegt heute unverifiziert im Bundle. Ohne eigene
Pruefung im unabhaengigen Verifier ist das Feld reine Dekoration (`no-demo-theater`, CLAUDE.md):
niemand ausser ALEX kann nachrechnen, ob die eingebettete Signatur tatsaechlich vom Private
Key des Freigebenden stammt. Ziel dieser Spec: `verify.ts` und `verify.py` rechnen die Signatur
unabhaengig vom ALEX-Server nach (keine DB, kein Netzwerk) und liefern zeichengenau dasselbe
Urteil.

## Scope

- Betroffen: `verify.ts`, `verify.py` (alex-mrtb-verify-bundle, dieses Repo). Kein alex-core-Code.
- Neue Prueffunktion `verifyWebauthnApprovalAssertionV1()` (TS) / Pendant in `verify.py`, additiv
  in `verifyVerifierBindingManifestV1()` aufgehaengt, analog zu `bundle.approval_attestation` und
  `bundle.rfc3161_timestamp` (Zeile 716-729 im bestehenden `verify.ts`).
- Keine neue externe Dependency. Weder `@simplewebauthn/server` (TS) noch `cryptography` (Python,
  hat die Codebase aktuell nicht -- Signaturen laufen durchgehend ueber `openssl`-Subprocess,
  siehe `openssl_verify()` in `verify.py` Zeile 116). Stattdessen: eigener, minimaler COSE-Key-
  Parser (Algorithmus-ID -> Ed25519 oder ECDSA-P256), der in beide bestehenden Pfade einspeist --
  TS: `crypto.verify()` direkt (wie bereits fuer andere Signaturen); Python: COSE -> PEM-Konvertierung,
  dann derselbe `openssl pkeyutl -verify`-Aufruf wie heute schon fuer Ed25519.
- Out of scope: Challenge-/Origin-Pruefung (`clientDataJSON.challenge`/`.origin`). Die Challenge ist
  zum Zeitpunkt der Verifikation laengst verbraucht; dieser Verifier bezeugt nur "dieser Private Key
  hat zu diesem Zeitpunkt ueber diese Daten signiert", nicht den WebAuthn-Ceremony-Ablauf selbst.

## Feldinventur (`WebauthnApprovalAssertionV1`, aus `core/mrtb/evidenceBundle.server.ts`)

`schema_version` ("webauthn-approval-assertion@1.0"), `credential_id`, `public_key` (base64, roher
COSE-Key, kein PEM), `signature`/`authenticator_data`/`client_data_json` (base64url, unveraendert
wie vom Browser/`@simplewebauthn/server` geliefert), `counter` (number).

Zu pruefender Payload: `signature` muss gueltig sein ueber
`authenticator_data || sha256(client_data_json)`, gegen den in `public_key` eingebetteten
oeffentlichen Schluessel.

## Given-When-Then

**G1 -- Feld fehlt (reiner Token-Pfad).**
Given ein Bundle ohne `controller_evidence.webauthn_approval_assertion`,
When `verifyWebauthnApprovalAssertionV1()` laeuft,
Then wird nichts geprueft und `verifyVerifierBindingManifestV1()` bleibt davon unberuehrt
(kein Fail, keine Aussage ueber WebAuthn-Staerke der Freigabe).

**G2 -- Feld vorhanden, Signatur gueltig.**
Given ein Bundle mit `webauthn_approval_assertion`, dessen `signature` korrekt ueber
`authenticator_data || sha256(client_data_json)` mit dem eingebetteten `public_key` erzeugt wurde,
When die Pruefung laeuft,
Then liefert sie `{ok: true}` und `verifyVerifierBindingManifestV1()` bleibt `{ok:true}` (sofern
sonst nichts dagegenspricht).

**G3a -- Feld vorhanden, Signatur ungueltig, innerhalb von `verifyVerifierBindingManifestV1()`
(manifest-Subcommand) -- Gesamt-Fail, konsistent mit Geschwister-Pattern DORT.**
Given ein Bundle mit `webauthn_approval_assertion`, dessen Signatur NICHT zum `public_key` passt
(falscher Key, manipulierte Bytes, falscher Payload),
When `verifyVerifierBindingManifestV1()` laeuft,
Then liefert sie `{ok:false, reason:"invalid_webauthn_assertion"}` -- Gesamt-Fail der Funktion,
exakt wie bei `approval_attestation`/`rfc3161_timestamp` INNERHALB DIESER FUNKTION (Zeile
716-729). Bewusst entschieden (Andre, 15.11.2026) nach Vorlage einer abweichenden Option ("eigener
Reason-Code ohne Gesamt-Fail") -- verworfen, weil sie dem bestehenden Pattern der beiden
Geschwisterfelder innerhalb dieser Funktion widersprochen haette.

**G3b -- Feld vorhanden, Signatur ungueltig, im Default-CLI-Pfad (`main()`, die eigentliche
alltaegliche Pruefung ohne `manifest`-Subcommand) -- Warnung, kein Gesamt-Fail.**
Given dasselbe Bundle wie G3a,
When der Default-Pfad laeuft (kein `manifest`-Subcommand),
Then bleibt das Bundle-Urteil unveraendert; `checks.webauthn_assertion` erhaelt den Reason-Code,
eine Warnzeile wird ausgegeben. Grund fuer die Abweichung von G3a: im Default-Pfad werden
`rfc3161_timestamp`/`observer_receipt` -- dieselbe Kategorie additiver, optionaler
Zusatzbeweisschicht wie `webauthn_approval_assertion` -- NACHWEISLICH ebenfalls nur als Warnung
behandelt ("ignoring it, bundle verdict above is unaffected", Zeile ~3822), waehrend
`approval_attestation` dort hart scheitert, aber nur weil es durch `approval_attestation_required`
zu einem PFLICHTfeld wird, keine optionale Zusatzschicht ist. `webauthn_approval_assertion` hat
kein eigenes `..._required`-Pflichtfeld, gehoert also kategorisch zur rfc3161/observer_receipt-
Gruppe, nicht zur approval_attestation-Gruppe. Dieser Fund entstand erst WAEHREND der
Implementierung (echter Code-Gegencheck von main(), nicht nur von
`verifyVerifierBindingManifestV1()`) und wurde Andre vorgelegt, bevor der Default-Pfad verdrahtet
wurde -- "das beste davon bitte" (empfohlene Option: Warnung, konsistent mit dem tatsaechlichen
Pattern dieses Pfades).

**G4 -- Zeichengenau gleiches Urteil TS/Python.**
Given dieselbe Bundle-Fixture (ein echter, aus einer realen Browser-Ceremony stammender
Assertion-Datensatz, erzeugt ueber `npx tsx tests/e2e/passkey-approval.e2e.ts` in alex-core,
keine handgebastelten Fake-Bytes),
When `verify.ts` UND `verify.py` unabhaengig voneinander laufen,
Then liefern beide denselben `ok`-Wert und denselben `reason`-String.

**G5 -- Unbekannte COSE-Algorithmus-ID.**
Given ein `public_key`, dessen COSE-Algorithmus-ID weder Ed25519 (-8/EdDSA) noch ECDSA-P256 (-7)
ist,
When die Pruefung laeuft,
Then liefert sie `{ok:false, reason:"unsupported_cose_algorithm"}` -- kein Crash, kein impliziter
Pass (Invariante 2, `INVARIANTS.md`: Unknown ist niemals gleichbedeutend mit Pass).

## Aenderungsregel

Additiv innerhalb von `controller_evidence`, keine neue `evidence-package`-Major-/Minor-Version
noetig (gleiches Muster wie `evidence_ref` in `devtask.execution@1.0.md`). Eine erfolgreiche
Pruefung erhoeht nicht automatisch die `claim_ladder`-Stufe der Freigabe selbst -- das ist eine
separate, hier nicht entschiedene Frage (Invariante 8: `strength` muss aus der Evidence ableitbar
sein, nicht vom Pruefcode zugewiesen werden). Diese Spec liefert nur die kryptographische
Nachpruefbarkeit; ob/wie sie sich auf `claim_ladder` auswirkt, ist ein moeglicher Folgeauftrag.
