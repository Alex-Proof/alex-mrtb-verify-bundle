import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import test from "node:test";
import { canonicalEvidenceJson, evaluateProofPolicy, evaluateTrustRequirement, validateDevTaskEvidenceSpecV1, verifyBundleObject, verifyValidationAttestation, verifyReviewerAttestation, crossCheckObserverReceipt } from "../dist/verify.js";

// 06.09.2026: einzige bewusste strukturelle Abweichung von der privaten Kopie in
// tools/verify-bundle/test/verify.test.mjs -- dort ist der Pfad "../../../spec/..." (drei Ebenen,
// weil die private Datei unter tools/verify-bundle/test/ liegt), hier "../spec/..." (eine Ebene,
// weil dieses oeffentliche Repo flach ist, spec/ liegt direkt im Repo-Root). Inhalt sonst identisch.
test("canonicalization goldfile binds identical UTF-8 bytes including spec_version", () => {
  const gold = JSON.parse(readFileSync(new URL("../spec/canonicalization-v1.gold.json", import.meta.url), "utf8"));
  const actual = canonicalEvidenceJson(gold.input);
  assert.equal(actual, gold.canonical_utf8);
  assert.equal(sha256(actual), gold.sha256);
});

test("Trust Model: mehrere schwache Signale duerfen keinen staerkeren Claim erzeugen", () => {
  const result = evaluateTrustRequirement("attested", [
    { artifact_id: "runtime-a", trust_level: "observed", provenance_resolved: true },
    { artifact_id: "runtime-b", trust_level: "observed", provenance_resolved: true },
    { artifact_id: "policy-c", trust_level: "policy_derived", provenance_resolved: true },
  ]);
  assert.deepEqual(result, { satisfied: false, effective_level: "unsupported", reason: "insufficient_trust_level" });
});

test("Trust Model: nur ein eigenstaendiges Artefakt auf Zielstufe stuetzt den Claim", () => {
  assert.deepEqual(evaluateTrustRequirement("independently_witnessed", [
    { artifact_id: "witness-1", trust_level: "independently_witnessed", provenance_resolved: true },
  ]), { satisfied: true, effective_level: "independently_witnessed", supporting_artifact_id: "witness-1" });
  assert.equal(evaluateTrustRequirement("observed", [
    { artifact_id: "missing", trust_level: "observed", provenance_resolved: false },
  ]).satisfied, false);
});

test("Trust Model: gueltige Kryptographie erhoeht die semantische Trust-Stufe nicht", () => {
  assert.deepEqual(evaluateTrustRequirement("independently_witnessed", [
    { artifact_id: "agent-signature", trust_level: "cryptographically_verified", provenance_resolved: true, semantic_trust_level: "observed" },
  ]), { satisfied: false, effective_level: "unsupported", reason: "insufficient_trust_level" });
});

const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` :
  value && typeof value === "object" ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}` : JSON.stringify(value);
const sha256 = value => createHash("sha256").update(value).digest("hex");

function hashChain(events) {
  const chain = [];
  let previous = "genesis";
  for (const event of events) {
    previous = createHash("sha256").update(previous + event).digest("hex");
    chain.push(previous);
  }
  return chain;
}

function signedBundle({ events, outcome = "verified" }) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const payload = {
    bundle_id: "public_test_bundle",
    capability: "memory.provenance.attached@1.0",
    run_id: "public_test_run",
    claim_ladder: "L2",
    executed_at: "2026-08-20T00:00:00.000Z",
    trace_events: events,
    trace_hash_chain: hashChain(events),
    outcome,
  };
  return {
    ...payload,
    signature: sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64"),
    public_key: publicKey.export({ type: "spki", format: "pem" }),
  };
}

const verifiedEvent = "memory_write:{\"entry_id\":\"entry-1\",\"actual_agent_id\":\"agent-a\",\"provenance_agent_id\":\"agent-a\",\"actual_source_hash\":\"hash-a\",\"provenance_source_hash\":\"hash-a\"}";
const contradictoryEvent = "memory_write:{\"entry_id\":\"entry-1\",\"actual_agent_id\":\"agent-a\",\"provenance_agent_id\":\"agent-b\",\"actual_source_hash\":\"hash-a\",\"provenance_source_hash\":\"hash-a\"}";

test("accepts a correctly signed verified provenance bundle", () => {
  assert.deepEqual(verifyBundleObject(signedBundle({ events: [verifiedEvent] })), { ok: true });
});

test("rejects a bundle changed after signing", () => {
  const bundle = signedBundle({ events: [verifiedEvent] });
  bundle.trace_events[0] = contradictoryEvent;
  assert.deepEqual(verifyBundleObject(bundle), { ok: false, reason: "invalid_signature" });
});

test("keeps missing evidence inconclusive", () => {
  const result = verifyBundleObject(signedBundle({ events: [], outcome: "inconclusive" }));
  assert.deepEqual(result, { ok: false, reason: "non_verified_outcome:inconclusive" });
});

test("rejects a verified claim contradicted by its trace", () => {
  const result = verifyBundleObject(signedBundle({ events: [contradictoryEvent] }));
  assert.deepEqual(result, {
    ok: false,
    reason: "trace_outcome_mismatch:declared=verified:derived=failed",
  });
});

test("rejects a self-signed forgery that declares an unrecognized evidence-package schema version", () => {
  // 01.09.2026: Regressionstest fuer einen echten Fund -- vor dem Fix lief jeder schema_version-
  // Wert ausser exakt "evidence-package@2.0" komplett am Trust-Anchor-Pinning vorbei, die
  // Signaturpruefung verifizierte dann nur noch gegen den im Bundle selbst mitgelieferten
  // public_key. Eine Faelschung, die diese Luecke ausnutzen wollte, brauchte nie den echten
  // privaten Schluessel -- nur einen abweichenden schema_version-String.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const payload = {
    schema_version: "evidence-package@9.9",
    bundle_id: "forged_bundle",
    capability: "devtask.execution@1.0",
    run_id: "forged_run",
    claim_ladder: "L2",
    executed_at: "2026-09-01T00:00:00.000Z",
    trace_events: [],
    trace_hash_chain: hashChain([]),
    outcome: "verified",
  };
  const forged = {
    ...payload,
    signature: sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64"),
    public_key: publicKey.export({ type: "spki", format: "pem" }),
  };
  // Trust-Anchor gar nicht erst uebergeben -- eine echte Fremdpartei haette ihn ohnehin nicht.
  assert.deepEqual(verifyBundleObject(forged), { ok: false, reason: "unsupported_schema_version" });
});

// 01.09.2026: lokale Kopie von buildCustomerSummaryDe() aus verify.ts, nur zum Bau von
// Test-Fixtures (gleiches Prinzip wie canonical() oben -- das Original ist nicht exportiert).
// Diese Kopie erzeugt das erwartete Summary fuer einen GUELTIGEN Testfall; sie testet nicht sich
// selbst, sondern liefert nur die Eingabedaten fuer verifyBundleObject().
function testSummary({ brief, cost_partial, denied, approval }) {
  const lines = [brief.title, "", "Auftrag:", brief.raw_text, "", "Kosten:"];
  if (cost_partial.cost_usd_tracked && cost_partial.cost_usd !== null) {
    const parts = [`$${cost_partial.cost_usd.toFixed(2)}`];
    if (cost_partial.turns_used !== null) parts.push(`${cost_partial.turns_used} Turns`);
    if (cost_partial.duration_seconds !== null) {
      const m = Math.floor(cost_partial.duration_seconds / 60);
      const s = Math.floor(cost_partial.duration_seconds % 60);
      parts.push(`${m}m ${s}s`);
    }
    lines.push(parts.join(", "));
  } else {
    lines.push(`Kosten nicht erfasst (externe CLI-Engine \`${cost_partial.assigned_engine}\`, kein Kostentracking für diesen Pfad).`);
  }
  lines.push("Es werden ausschließlich Aggregatkosten erfasst, keine Tokenzahlen.", "", "Freigabe:");
  if (approval.actor_id === null) lines.push("Keine Freigabe protokolliert.");
  else if (approval.proven) lines.push(`Bewiesen freigegeben über Kanal \`${approval.channel}\`.`);
  else lines.push(`Freigegeben über Kanal \`${approval.channel}\`, Identität nicht unabhängig bewiesen.`);
  if (approval.confirmed_by !== null) lines.push(`Bestätigt von: ${approval.confirmed_by}`);
  if (approval.confirmed_at !== null) lines.push(`Bestätigt am: ${approval.confirmed_at}`);
  lines.push("", "Abgelehnte Aktionen:");
  if (denied.length === 0) lines.push("Keine abgelehnten Aktionen in diesem Lauf.");
  else for (const d of [...denied].sort((a, b) => (a.path < b.path ? -1 : 1))) lines.push(`- ${d.path} (${d.reason})`);
  return lines.join("\n");
}

function devTaskV21Bundle({ tamperSummary = false, omitCustomerEvidence = false, mismatchApprovalRef = false } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const controllerEvidence = {
    producer: "privileged_controller", task_id: "task-1", attempt_number: 1,
    base_commit: null, result_reference: null, diff_stat_sha256: null, diff_full: null, diff_full_sha256: null,
    execution_reference: null, validation_reference: null, approval_reference: "dev_tasks.approved_by",
    sandbox_reference: null, sandbox_attestation: null, agent_run_id: null,
  };
  const brief = { title: "Testauftrag", raw_text: "Bitte README ergänzen." };
  const cost_partial = { cost_usd: 1.23, cost_usd_tracked: true, turns_used: 3, duration_seconds: 90, assigned_model: "deepseek-v4-flash", assigned_engine: "deepseek", token_tracking: "not_available" };
  const denied = [];
  const approval = {
    proven: true, actor_id: "andre", channel: "pilot", confirmed_by: "andre", confirmed_at: "2026-09-01T00:00:00.000Z",
    approved_at: "2026-09-01T00:00:00.000Z", approval_reference: mismatchApprovalRef ? "WRONG" : controllerEvidence.approval_reference,
  };
  const customer_evidence = omitCustomerEvidence ? undefined : {
    schema_version: "customer-evidence@1.0", brief, cost_partial, denied, approval,
    customer_summary: tamperSummary ? "manipuliert" : testSummary({ brief, cost_partial, denied, approval }),
  };
  const payload = {
    schema_version: "evidence-package@2.1",
    bundle_id: "test_devtask_bundle", capability: "devtask.execution@1.0", run_id: "task-1:1",
    claim_ladder: "L0", executed_at: "2026-09-01T00:00:00.000Z",
    trace_events: [], trace_hash_chain: hashChain([]), outcome: "inconclusive",
    signer_key_id: `ed25519:${sha256(pem)}`, controller_evidence: controllerEvidence,
    // riskRank() faellt bei unbekannter/fehlender risk_class (kein contract-Event) fail-safe auf
    // die hoechste Stufe (4) zurueck -- das erzwingt zusaetzlich "sandbox_attestation".
    required_evidence: ["contract", "attempt", "execution_context", "validation", "outcome", "base_commit", "diff_full", "sandbox_attestation"],
    customer_evidence,
  };
  return {
    ...payload,
    signature: sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64"),
    public_key: pem,
    _trustedPublicKey: pem,
  };
}

test("evidence-package@2.1: a correct customer_evidence block passes through to the standard outcome check", () => {
  const bundle = devTaskV21Bundle();
  const { _trustedPublicKey, ...clean } = bundle;
  const result = verifyBundleObject(clean, _trustedPublicKey);
  // Absichtlich "inconclusive" (leere trace_events, kein voller devtask-Lauf simuliert) -- waere
  // hier eine der NEUEN 2.1-Pruefungen faelschlich fehlgeschlagen, stuende ein anderer reason.
  assert.deepEqual(result, { ok: false, reason: "non_verified_outcome:inconclusive" });
});

test("evidence-package@2.1: rejects a bundle missing customer_evidence entirely", () => {
  const bundle = devTaskV21Bundle({ omitCustomerEvidence: true });
  const { _trustedPublicKey, ...clean } = bundle;
  assert.equal(verifyBundleObject(clean, _trustedPublicKey).reason, "missing_customer_evidence");
});

test("evidence-package@2.1: rejects a tampered customer_summary", () => {
  const bundle = devTaskV21Bundle({ tamperSummary: true });
  const { _trustedPublicKey, ...clean } = bundle;
  assert.equal(verifyBundleObject(clean, _trustedPublicKey).reason, "customer_summary_mismatch");
});

test("evidence-package@2.1: rejects a customer_evidence.approval.approval_reference that diverges from controller_evidence", () => {
  const bundle = devTaskV21Bundle({ mismatchApprovalRef: true });
  const { _trustedPublicKey, ...clean } = bundle;
  assert.equal(verifyBundleObject(clean, _trustedPublicKey).reason, "customer_approval_reference_mismatch");
});

test("evidence-package@2.2: rejects a missing spec_version before trusting the package", () => {
  const bundle = devTaskV21Bundle();
  const { _trustedPublicKey, ...clean } = bundle;
  clean.schema_version = "evidence-package@2.2";
  delete clean.spec_version;
  assert.deepEqual(verifyBundleObject(clean, _trustedPublicKey), {
    ok: false,
    reason: "spec_validation_failed:missing_required_field:spec_version",
  });
});

test("evidence-package@2.2: ignores unknown fields semantically but binds them cryptographically", () => {
  const bundle = devTaskV21Bundle();
  const { _trustedPublicKey, ...clean } = bundle;
  clean.schema_version = "evidence-package@2.2";
  clean.spec_version = "devtask.execution@1.0";
  clean.approval_attestation_required = false;
  clean.unfrozen_field = true;
  assert.equal(validateDevTaskEvidenceSpecV1(clean), null);
});

test("accepts independent validation only for the trusted runner and exact commit", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const environment = { image_digest: `node@sha256:${"a".repeat(64)}`, network: "none" };
  const payload = { schema_version: "validation-attestation@1.0", producer: "independent_evidence_runner", repository_commit: "commit-a",
    environment, environment_sha256: sha256(canonical(environment)), started_at: "2026-08-27T00:00:00Z", completed_at: "2026-08-27T00:01:00Z",
    duration_ms: 60000, exit_code: 0, passed: true, stdout_sha256: "b".repeat(64), stderr_sha256: "c".repeat(64), report_sha256: "d".repeat(64) };
  const attestation = { ...payload, signer_key_id: `ed25519:${sha256(pem)}`, public_key: pem,
    signature: sign(null, Buffer.from(canonical(payload)), privateKey).toString("base64") };
  assert.deepEqual(verifyValidationAttestation(attestation, pem, "commit-a"), { ok: true });
  assert.equal(verifyValidationAttestation(attestation, pem, "commit-b").reason, "validation_scope_mismatch");
});

test("reviewer signature binds the exact bundle and validation bytes", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const bundle = Buffer.from("bundle"); const validation = Buffer.from("validation");
  const payload = { schema_version: "reviewer-attestation@1.0", reviewer_id: "reviewer-server-1", decision: "approved",
    reviewed_at: "2026-08-27T00:02:00Z", bundle_sha256: sha256(bundle), validation_attestation_sha256: sha256(validation) };
  const attestation = { ...payload, reviewer_key_id: `ed25519:${sha256(pem)}`, public_key: pem,
    signature: sign(null, Buffer.from(canonical(payload)), privateKey).toString("base64") };
  assert.deepEqual(verifyReviewerAttestation(attestation, pem, bundle, validation), { ok: true });
  assert.equal(verifyReviewerAttestation(attestation, pem, Buffer.from("changed"), validation).reason, "review_scope_mismatch");
});

// Bauanleitung Evidence-Standard, Punkt 3 (06.09.2026): "Proof Policies" -- Mindestbeweislage vor
// einer als "gated" markierten Aktion. Testpolicy mit allen fuenf Bedingungen, jede einzeln
// gebrochen bzw. alle gemeinsam erfuellt.
const proofPolicyUnderTest = {
  policy_id: "test.pilot_pr_approve@1.0", gates_action: "test_gated_action",
  requires: {
    outcome: "verified", claim_ladder_min: "L1", human_approval: "required",
    no_unsupported_required_claims: true, independent_witness: "required",
  },
};
const allSatisfiedChecks = { signature: "ok", hash_chain: "ok", observer_inclusion: "ok" };
function proofPolicyBundle(overrides = {}) {
  return { bundle_id: "ppg-1", run_id: "ppg-run-1", executed_at: "2026-09-06T00:00:00.000Z",
    outcome: "verified", claim_ladder: "L1", approval_attestation_required: true, trace_events: [], ...overrides };
}

test("evaluateProofPolicy: alle Bedingungen erfuellt -> laeuft ungehindert durch", () => {
  const result = evaluateProofPolicy(proofPolicyUnderTest, proofPolicyBundle(), { effectiveClaimLadder: "L1", verifierChecks: allSatisfiedChecks });
  assert.deepEqual(result, {
    policy_id: "test.pilot_pr_approve@1.0", gates_action: "test_gated_action", allowed: true, blocked_by: [],
    evaluated: {
      outcome: { required: "verified", satisfied: true },
      claim_ladder_min: { required: "L1", satisfied: true },
      human_approval: { required: "required", satisfied: true },
      no_unsupported_required_claims: { required: true, satisfied: true },
      independent_witness: { required: "required", satisfied: true },
    },
  });
});

test("evaluateProofPolicy: outcome != verified blockiert -- nachweislich, nicht nur protokolliert", () => {
  const result = evaluateProofPolicy(proofPolicyUnderTest, proofPolicyBundle({ outcome: "inconclusive" }), { effectiveClaimLadder: "L1", verifierChecks: allSatisfiedChecks });
  assert.equal(result.allowed, false);
  assert.deepEqual(result.blocked_by, ["outcome"]);
});

test("evaluateProofPolicy: Claim-Ladder unterhalb des Minimums blockiert", () => {
  const result = evaluateProofPolicy(proofPolicyUnderTest, proofPolicyBundle(), { effectiveClaimLadder: "L0", verifierChecks: allSatisfiedChecks });
  assert.equal(result.allowed, false);
  assert.deepEqual(result.blocked_by, ["claim_ladder_min"]);
});

test("evaluateProofPolicy: fehlende human_approval blockiert", () => {
  const result = evaluateProofPolicy(proofPolicyUnderTest, proofPolicyBundle({ approval_attestation_required: false }), { effectiveClaimLadder: "L1", verifierChecks: allSatisfiedChecks });
  assert.equal(result.allowed, false);
  assert.deepEqual(result.blocked_by, ["human_approval"]);
});

test("evaluateProofPolicy: ein required Claim mit falsch aufloesender Provenance blockiert no_unsupported_required_claims", () => {
  // Ein fehlendes evidence_ref allein bleibt (Backward-Compat, spec/devtask.execution@1.0.md
  // "Optionale Claim-Provenance") bewusst informativ -- erst ein VORHANDENES, aber falsch
  // aufloesendes evidence_ref macht einen observed/attested-Claim "required: true, supported: false"
  // (assessClaimEvidenceRefs() Reason "digest_mismatch").
  const unsupportedClaimEvent = "devtask_negative_claim:" + JSON.stringify({
    task_id: "t", attempt_number: 1, claim: "no_secret_access", verified_by: "sandbox", strength: "observed", result: true,
    evidence_ref: { artifact: "runtime_trace", id: "trace_events:without_negative_claims", digest: "sha256:" + "0".repeat(64) },
  });
  const result = evaluateProofPolicy(proofPolicyUnderTest, proofPolicyBundle({ trace_events: [unsupportedClaimEvent] }), { effectiveClaimLadder: "L1", verifierChecks: allSatisfiedChecks });
  assert.equal(result.allowed, false);
  assert.deepEqual(result.blocked_by, ["no_unsupported_required_claims"]);
});

test("evaluateProofPolicy: independent_witness ist nur erfuellt, wenn der Verifier selbst eine echte Observer-Bestaetigung geliefert hat (echter lokaler Server, kein Mock)", async () => {
  const baseBundle = proofPolicyBundle();

  // Blockiert: kein observer_receipt vorhanden -- crossCheckObserverReceipt() braucht dafuer
  // keinen Netzwerkaufruf, liefert real "not_applicable_no_observer_receipt".
  const noReceiptResult = await crossCheckObserverReceipt(baseBundle);
  assert.deepEqual(noReceiptResult, { ok: false, reason: "not_applicable_no_observer_receipt" });
  const blockedChecks = { signature: "ok", hash_chain: "ok", observer_inclusion: noReceiptResult.reason };
  const blockedEvaluation = evaluateProofPolicy(proofPolicyUnderTest, baseBundle, { effectiveClaimLadder: "L1", verifierChecks: blockedChecks });
  assert.equal(blockedEvaluation.allowed, false);
  assert.deepEqual(blockedEvaluation.blocked_by, ["independent_witness"]);

  // Erlaubt: echter lokaler Observer-Stub, echter fetch(), echte Merkle-Pruefung nach RFC 6962
  // (Ein-Blatt-Baum: audit_path leer, root_hash == leaf hash) -- kein Mock von
  // crossCheckObserverReceipt() selbst, derselbe Code laeuft wie gegen den echten Observer-Dienst.
  const receivedAt = "2026-09-06T00:00:05.000Z";
  const expectedBundleSha256 = sha256(JSON.stringify(baseBundle));
  const leafHash = createHash("sha256").update(Buffer.concat([Buffer.from([0x00]), Buffer.from(JSON.stringify({
    bundle_id: baseBundle.bundle_id, bundle_sha256: expectedBundleSha256, run_id: baseBundle.run_id,
    executed_at: baseBundle.executed_at, received_at: receivedAt,
  }))])).digest("hex");

  const server = createServer((req, res) => {
    if (req.url === `/observer/receipt/${baseBundle.bundle_id}`) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ found: true, bundle_sha256: expectedBundleSha256, received_at: receivedAt, inclusion: { audit_path: [], root_hash: leafHash }, anchor: { status: "pending" } }));
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((resolve) => server.listen(0, resolve));
  try {
    const address = server.address();
    const observerUrl = `http://127.0.0.1:${address.port}`;
    const bundleWithReceipt = { ...baseBundle, observer_receipt: { schema_version: "observer-receipt@1.0", observer_url: observerUrl, leaf_index: 0, received_at: receivedAt } };
    const confirmedResult = await crossCheckObserverReceipt(bundleWithReceipt);
    assert.deepEqual(confirmedResult, { ok: true, anchor_status: "pending" });
    const allowedChecks = { signature: "ok", hash_chain: "ok", observer_inclusion: "ok" };
    const allowedEvaluation = evaluateProofPolicy(proofPolicyUnderTest, bundleWithReceipt, { effectiveClaimLadder: "L1", verifierChecks: allowedChecks });
    assert.equal(allowedEvaluation.allowed, true);
    assert.deepEqual(allowedEvaluation.blocked_by, []);
  } finally {
    server.close();
  }
});
