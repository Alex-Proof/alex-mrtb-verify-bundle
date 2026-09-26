import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { verifyEpistemicGateBinding, buildVerdictArtifactV1, verifyVerdictArtifactV1 } from "../dist/verify.js";

// 26.09.2026 (Iman/EMILIA-Protocol, SCITT-Mailingliste): drei konkrete Testfaelle angefragt fuer
// ein nachtraeglich geaendertes/entferntes/repliziertes epistemic_gate-Attestat. Die Fixtures hier
// sind KEINE synthetischen Beispiele -- sie sind byte-fuer-byte von den beiden bereits
// veroeffentlichten, echten Canary-Bundles abgeleitet (network-egress-deny-canary-14.json,
// cline-acp-canary-13.json), damit der Verifier gegen echte Produktionssignaturen prueft, nicht
// gegen ein Testfixture mit Testschluessel.
const trustedKey = JSON.parse(readFileSync(new URL("../trust-anchor.json", import.meta.url), "utf8")).public_key_pem;
const loadBundle = (name) => JSON.parse(readFileSync(new URL(`../${name}`, import.meta.url), "utf8"));

test("verifyEpistemicGateBinding: akzeptiert die beiden echten, unveraenderten Canary-Bundles", () => {
  assert.deepEqual(verifyEpistemicGateBinding(loadBundle("network-egress-deny-canary-14.json"), trustedKey), { ok: true });
  assert.deepEqual(verifyEpistemicGateBinding(loadBundle("cline-acp-canary-13.json"), trustedKey), { ok: true });
});

test("verifyEpistemicGateBinding: fehlendes Attestat -> epistemic_gate_not_attached", () => {
  const result = verifyEpistemicGateBinding(loadBundle("epistemic-gate-removed.json"), trustedKey);
  assert.deepEqual(result, { ok: false, reason: "epistemic_gate_not_attached" });
});

test("verifyEpistemicGateBinding: nachtraeglich geaendertes Gate (decision) -> invalid_epistemic_gate_signature", () => {
  const result = verifyEpistemicGateBinding(loadBundle("epistemic-gate-changed.json"), trustedKey);
  assert.deepEqual(result, { ok: false, reason: "invalid_epistemic_gate_signature" });
});

test("verifyEpistemicGateBinding: aus einem anderen Bundle repliziertes Gate -> epistemic_gate_hash_mismatch", () => {
  const result = verifyEpistemicGateBinding(loadBundle("epistemic-gate-replayed.json"), trustedKey);
  assert.deepEqual(result, { ok: false, reason: "epistemic_gate_hash_mismatch" });
});

// 26.09.2026, zweiter Iman/EMILIA-Protocol-Fund: ein an ein Verdict Artifact angehaengtes,
// nachtraeglich geaendertes epistemic_gate blieb bisher auf dem NORMALEN Verdict-Pfad unentdeckt --
// verifyEpistemicGateBinding() musste bisher separat/manuell aufgerufen werden. verifyVerdictArtifactV1()
// ruft es jetzt automatisch mit auf, sobald ein epistemic_gate angehaengt ist.
const verifierBuild = "sha256:" + "c".repeat(64);

test("verifyVerdictArtifactV1: lehnt ein angehaengtes, nachtraeglich geaendertes Gate ab (vorher unentdeckt)", () => {
  const bundle = loadBundle("network-egress-deny-canary-14.json");
  const artifact = buildVerdictArtifactV1(bundle, verifierBuild);
  const tampered = structuredClone(artifact);
  tampered.source_bundle.epistemic_gate.gate.decision = "acted";
  assert.deepEqual(
    verifyVerdictArtifactV1(tampered, trustedKey, verifierBuild),
    { ok: false, reason: "epistemic_gate_invalid_epistemic_gate_signature" },
  );
});

test("verifyVerdictArtifactV1: ein unveraendertes, angehaengtes Gate laesst das Verdict weiterhin gueltig", () => {
  const bundle = loadBundle("network-egress-deny-canary-14.json");
  const artifact = buildVerdictArtifactV1(bundle, verifierBuild);
  const source = verifyVerdictArtifactV1(artifact, trustedKey, verifierBuild);
  // Der Canary selbst ist non_verified_outcome:failed (kein erfolgreicher Auftrag) -- die
  // epistemic_gate-Pruefung laeuft trotzdem durch, das ist ein separater, unabhaengiger Check.
  assert.equal(source.ok, true);
});
