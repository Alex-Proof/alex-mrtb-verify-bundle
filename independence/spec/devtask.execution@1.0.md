# devtask.execution@1.0

Status: eingefroren am 2026-09-06. Normatives Schema: `devtask.execution@1.0.schema.json`.
Massstab: `INVARIANTS.md`.

## Formatgrenze

`spec_version` benennt den fachlichen Vertrag. `schema_version` benennt den Container.
Neue Pakete dieser Spec verwenden `evidence-package@2.2`. Historische Container 2.0 und 2.1
bleiben mit ihrer damaligen Semantik pruefbar, sind aber keine konformen Neuerzeugungen von
`devtask.execution@1.0`.

## Inventur der tatsaechlich verwendeten Felder

Pflichtfelder sind im JSON-Schema unter `required` festgelegt. Der Verifier liest und prueft:

- Identitaet und Bindung: `bundle_id`, `run_id`, `capability`, `spec_version`,
  `schema_version`, `executed_at`.
- Integritaet: `signature`, `public_key`, `signer_key_id`, `trace_events`,
  `trace_hash_chain`.
- Aussage: `claim_ladder`, `outcome`, `required_evidence`.
- Controller-Provenance: `controller_evidence` einschliesslich Contract-Snapshot,
  Repository-Zustand, Sandbox-Attestation, Testschutz und Ereignisreferenzen.
- Freigabe: `approval_attestation_required` und optional `approval_attestation`.
- Optionale, signierte Leseschicht: `customer_evidence`.
- Optionale, nach der Paketsignatur angehaengte Artefakte: `rfc3161_timestamp` und
  `observer_receipt`. Sie werden separat gebunden und duerfen die semantische Claim-Stufe
  nicht durch Kombination erhoehen.

## Claim-Ladder

Das signierte Package darf L0, L1 oder L2 tragen. L3 ist kein Package-Claim dieser Spec.
Ein unabhaengiger Reviewer kann bei seiner eigenen Pruefung eine separate L3-Aussage erzeugen,
wenn ein einzelnes, aufloesbares Reviewer-Artefakt die Anforderungen erfuellt.
RFC-3161 plus Observer ergibt nicht L3.

## Aenderungsregel

Additive optionale Felder innerhalb der explizit forward-kompatiblen Objektgrenzen benoetigen keine
neue Spec-Version. Sobald ein solches Feld Pflicht wird, benoetigt es eine neue Minor-Version oder
eine datierte Pflichtregel -- nicht beides gleichzeitig. Inkompatible Semantik benoetigt eine neue
Major-Version. Diese Datei und ihr Schema werden fuer
alte Packages nicht nachtraeglich umgedeutet.

Unbekannte Felder werden fuer Forward-Kompatibilitaet bei der semantischen Auswertung ignoriert,
bleiben aber durch die kanonische Signatur gebunden. Fehlende Pflichtfelder werden abgelehnt.
## Optionale Claim-Provenance (evidence_ref)

Ein devtask_negative_claim darf additiv eine Referenz mit artifact, id und digest tragen. artifact
ist einer von runtime_trace, attestation, ci_check oder signature; digest verwendet sha256:...

Das Feld bleibt in evidence-package@2.2 optional. Fehlt es, ist der Claim hinsichtlich seiner
Provenance unsupported, ohne alte Bundles abzulehnen. Ist es vorhanden, muss der Verifier ID,
Artefakttyp und Digest offline gegen den Bundle-Inhalt aufloesen. Eine nicht aufloesbare oder
falsche Referenz eines ladder-relevanten (observed/attested) Claims blockiert das Bundle. Ein
policy_derived-Claim bleibt auch mit gueltiger Referenz rein informatorisch.
