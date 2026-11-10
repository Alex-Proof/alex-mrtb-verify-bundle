import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  verifyEnforcementRecords,
  buildIncidentRecordsV1, detectObserverFailureIncident, detectEvidenceIntegrityFailureIncident,
  governanceIncidentGate,
  verifyDelegationChain, verifyDelegationLinkSignature, verifyDelegationChainSignatures,
  pinDelegationChainSigners, pinPolicyRef,
  buildGovernanceProvenanceV1, summarizeGovernanceProvenance, deriveLiveGovernanceProvenanceV1,
} from "../dist/verify.js";

// Phase 1 of the governance-layer sync (31.10.-09.11.2026 private build): these six foundation
// blocks (enforcement records, enforcement verification, delegation chains, policy-ref pinning,
// incident records, governance provenance) have no dependency on GovernanceTupleV1 yet (Phase 2).
// buildEnforcementRecordsV1() itself stays internal/unexported here, mirroring the private module
// exactly -- these tests exercise it only indirectly, through hand-built EnforcementRecordV1
// fixtures fed into the exported functions that consume its output.

// --- verifyEnforcementRecords: four states, fail-closed -------------------------------------

test("verifyEnforcementRecords: no records -> not_run", () => {
  assert.deepEqual(verifyEnforcementRecords([]), { status: "not_run", evidence_gaps: [] });
});

function enforcementRecord(overrides) {
  return {
    schema_version: "enforcement-record@1.0", record_id: "r1", constraint_id: "c1",
    control_type: "path", attempt: "x", result: "blocked", control_active_proof: "proof:1",
    observed_by: "enforcer", ts: "2026-11-10T00:00:00.000Z",
    ...overrides,
  };
}

test("verifyEnforcementRecords: all records proven -> enforced", () => {
  const records = [enforcementRecord({})];
  assert.deepEqual(verifyEnforcementRecords(records), { status: "enforced", evidence_gaps: [] });
});

test("verifyEnforcementRecords: at least one record without proof -> partial, never enforced (fail-closed)", () => {
  const withProof = enforcementRecord({});
  const withoutProof = enforcementRecord({ record_id: "r2", control_active_proof: null, observed_by: "agent_reported" });
  assert.deepEqual(verifyEnforcementRecords([withProof, withoutProof]), { status: "partial", evidence_gaps: ["r2"] });
});

test("verifyEnforcementRecords: ALL records without proof -> still only partial, never enforced", () => {
  const withoutProof = enforcementRecord({ record_id: "r2", control_active_proof: null, observed_by: "agent_reported" });
  assert.deepEqual(verifyEnforcementRecords([withoutProof]), { status: "partial", evidence_gaps: ["r2"] });
});

// --- buildIncidentRecordsV1: control_type -> incident_type mapping --------------------------

test("buildIncidentRecordsV1: maps each control_type to its incident_type, with evidence_status from control_active_proof", () => {
  const enforcement = [
    enforcementRecord({ record_id: "enforcement:c1:blocked_attempt:0", control_type: "egress", control_active_proof: "p" }),
    enforcementRecord({ record_id: "enforcement:c1:blocked_attempt:1", control_type: "secret", control_active_proof: null }),
    enforcementRecord({ record_id: "enforcement:c1:blocked_attempt:2", control_type: "path", control_active_proof: "p" }),
    enforcementRecord({ record_id: "enforcement:c1:blocked_attempt:3", control_type: "self_replication", control_active_proof: "p" }),
    enforcementRecord({ record_id: "enforcement:c1:blocked_attempt:4", control_type: "human_gate", control_active_proof: null }),
  ];
  const incidents = buildIncidentRecordsV1("tuple:1", enforcement);
  assert.equal(incidents.length, 5);
  assert.equal(incidents[0].incident_type, "unexpected_external_communication");
  assert.equal(incidents[0].evidence_status, "complete");
  assert.equal(incidents[1].incident_type, "unauthorized_access_attempt");
  assert.equal(incidents[1].evidence_status, "gap");
  assert.equal(incidents[2].incident_type, "sandbox_escape_attempt");
  assert.equal(incidents[3].incident_type, "sandbox_escape_attempt");
  assert.equal(incidents[4].incident_type, "approval_bypass_attempt");
});

test("buildIncidentRecordsV1: privilege splits into policy_violation vs delegation_violation by record_id", () => {
  const enforcement = [
    enforcementRecord({ record_id: "enforcement:c1:blocked_attempt:0", control_type: "privilege" }),
    enforcementRecord({ record_id: "enforcement:c1:delegation_denial:0", control_type: "privilege" }),
  ];
  const incidents = buildIncidentRecordsV1("tuple:1", enforcement);
  assert.equal(incidents[0].incident_type, "policy_violation");
  assert.equal(incidents[1].incident_type, "delegation_violation");
});

test("detectObserverFailureIncident: only fires when a receipt is present but the cross-check failed", () => {
  assert.equal(detectObserverFailureIncident("t1", { observerReceiptPresent: false, observerConfirmed: null }), null);
  assert.equal(detectObserverFailureIncident("t1", { observerReceiptPresent: true, observerConfirmed: true }), null);
  const incident = detectObserverFailureIncident("t1", { observerReceiptPresent: true, observerConfirmed: false });
  assert.equal(incident.incident_type, "observer_failure");
  assert.equal(incident.evidence_status, "gap");
});

test("detectEvidenceIntegrityFailureIncident: null when signature and hash chain both hold, otherwise a gap incident", () => {
  assert.equal(detectEvidenceIntegrityFailureIncident("t1", { signatureOk: true, hashChainOk: true }), null);
  const sigFail = detectEvidenceIntegrityFailureIncident("t1", { signatureOk: false, hashChainOk: true });
  assert.equal(sigFail.detail, "signature_invalid");
  const chainFail = detectEvidenceIntegrityFailureIncident("t1", { signatureOk: true, hashChainOk: false });
  assert.equal(chainFail.detail, "hash_chain_invalid");
  const withReason = detectEvidenceIntegrityFailureIncident("t1", { signatureOk: false, hashChainOk: false, reason: "custom_reason" });
  assert.equal(withReason.detail, "custom_reason");
});

test("governanceIncidentGate: observer_failure/evidence_integrity_failure block, every other incident type does not", () => {
  const nonBlocking = buildIncidentRecordsV1("t1", [enforcementRecord({ control_type: "egress" })]);
  assert.deepEqual(governanceIncidentGate(nonBlocking), { max_status: "verified", blocking_incidents: [] });

  const blocking = [detectObserverFailureIncident("t1", { observerReceiptPresent: true, observerConfirmed: false })];
  const gate = governanceIncidentGate(blocking);
  assert.equal(gate.max_status, "partial");
  assert.deepEqual(gate.blocking_incidents, [blocking[0].incident_id]);
});

// --- Delegation chain: real Ed25519-signed principal -> A -> B -> Tool chain ----------------

function makeKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    privateKey,
  };
}

function canonicalUnsigned(link) {
  const { signature, ...unsigned } = link;
  const sortedStringify = (value) => {
    if (Array.isArray(value)) return `[${value.map(sortedStringify).join(",")}]`;
    if (value && typeof value === "object") {
      return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${sortedStringify(value[k])}`).join(",")}}`;
    }
    return JSON.stringify(value);
  };
  return sortedStringify(unsigned);
}

function signLink(link, keypair) {
  const bytes = Buffer.from(canonicalUnsigned(link), "utf8");
  const signature = sign(null, bytes, keypair.privateKey).toString("base64");
  return { ...link, signature: { algorithm: "ed25519", public_key: keypair.publicKeyPem, signature } };
}

function buildChain(approvalKeypair) {
  const rootLink = signLink({
    schema_version: "delegation-link@1.0", delegation_id: "delegation:agent-A",
    parent: { kind: "principal", id: "requester-1" }, child: "agent-A",
    scope: { tool_manifest: ["read_file", "write_file", "shell"], data_access: ["ingest_url"], max_runtime_ms: 600000 },
    valid_from: "2026-11-10T00:00:00.000Z", valid_until: "2026-11-10T01:00:00.000Z",
    revocable: false, revoked_at: null, inherited_constraints: [], parent_delegation_id: null,
  }, approvalKeypair);
  const linkB = signLink({
    schema_version: "delegation-link@1.0", delegation_id: "delegation:agent-B",
    parent: { kind: "agent", id: "agent-A" }, child: "agent-B",
    scope: { tool_manifest: ["read_file", "write_file"], data_access: ["ingest_url"], max_runtime_ms: 300000 },
    valid_from: "2026-11-10T00:00:00.000Z", valid_until: "2026-11-10T01:00:00.000Z",
    revocable: false, revoked_at: null, inherited_constraints: [], parent_delegation_id: "delegation:agent-A",
  }, approvalKeypair);
  const linkTool = signLink({
    schema_version: "delegation-link@1.0", delegation_id: "delegation:agent-Tool",
    parent: { kind: "agent", id: "agent-B" }, child: "agent-Tool",
    scope: { tool_manifest: ["read_file"], data_access: [], max_runtime_ms: 60000 },
    valid_from: "2026-11-10T00:00:00.000Z", valid_until: "2026-11-10T01:00:00.000Z",
    revocable: false, revoked_at: null, inherited_constraints: [], parent_delegation_id: "delegation:agent-B",
  }, approvalKeypair);
  return [rootLink, linkB, linkTool];
}

test("verifyDelegationChain: happy path principal -> A -> B -> Tool, each link a real subset of its parent -> verified", () => {
  const chain = buildChain(makeKeypair());
  assert.deepEqual(verifyDelegationChain(chain), { status: "verified" });
});

test("verifyDelegationChain: empty chain -> not_run, never verified", () => {
  assert.deepEqual(verifyDelegationChain([]), { status: "not_run" });
});

test("verifyDelegationChain: does not start at a principal -> failed", () => {
  const chain = buildChain(makeKeypair());
  chain[0].parent = { kind: "agent", id: "some-agent" };
  const result = verifyDelegationChain(chain);
  assert.equal(result.status, "failed");
  assert.equal(result.reason, "chain_does_not_start_at_principal");
  assert.equal(result.link_id, chain[0].delegation_id);
});

test("verifyDelegationChain: missing link (B skipped) -> chain_broken, failed", () => {
  const chain = buildChain(makeKeypair());
  const broken = [chain[0], chain[2]];
  const result = verifyDelegationChain(broken);
  assert.equal(result.status, "failed");
  assert.equal(result.reason, "chain_broken");
  assert.equal(result.link_id, chain[2].delegation_id);
});

test("verifyDelegationChain: privilege escalation (B claims a tool A never had) -> failed", () => {
  const chain = buildChain(makeKeypair());
  chain[1].scope.tool_manifest = [...chain[1].scope.tool_manifest, "browser_create_account"];
  const result = verifyDelegationChain(chain);
  assert.equal(result.status, "failed");
  assert.equal(result.reason, "privilege_escalation");
  assert.equal(result.link_id, chain[1].delegation_id);
});

test("verifyDelegationLinkSignature / verifyDelegationChainSignatures: verified, unsigned, invalid, and mixed states", () => {
  const keypair = makeKeypair();
  const chain = buildChain(keypair);
  for (const link of chain) {
    assert.deepEqual(verifyDelegationLinkSignature(link), { status: "verified", link_id: link.delegation_id });
  }
  assert.deepEqual(verifyDelegationChainSignatures(chain), { status: "verified", unsigned_links: [], invalid_links: [] });

  const unsignedLink = { ...chain[2], signature: null };
  assert.deepEqual(verifyDelegationLinkSignature(unsignedLink), { status: "unsigned", link_id: unsignedLink.delegation_id });

  const tamperedAfterSigning = structuredClone(chain[1]);
  tamperedAfterSigning.scope.max_runtime_ms = 999999999;
  assert.deepEqual(verifyDelegationLinkSignature(tamperedAfterSigning), { status: "invalid", link_id: tamperedAfterSigning.delegation_id });

  const mixedInvalidAndUnsigned = structuredClone(chain);
  mixedInvalidAndUnsigned[1].scope.max_runtime_ms = 1;
  mixedInvalidAndUnsigned[2].signature = null;
  assert.deepEqual(verifyDelegationChainSignatures(mixedInvalidAndUnsigned), {
    status: "invalid", unsigned_links: [mixedInvalidAndUnsigned[2].delegation_id], invalid_links: [mixedInvalidAndUnsigned[1].delegation_id],
  });

  const onlyUnsigned = structuredClone(chain);
  onlyUnsigned[2].signature = null;
  assert.deepEqual(verifyDelegationChainSignatures(onlyUnsigned), {
    status: "partial", unsigned_links: [onlyUnsigned[2].delegation_id], invalid_links: [],
  });
});

// --- Delegation signer pinning (trust-anchor pinning for the embedded signing key) ----------

test("pinDelegationChainSigners: not_applicable for an unsigned chain, not_checked without a trusted key, pinned/not_pinned otherwise", () => {
  const unsignedChain = [{ ...buildChain(makeKeypair())[0], signature: null }];
  assert.deepEqual(pinDelegationChainSigners(unsignedChain, "whatever"), { status: "not_applicable", unpinned_links: [] });

  const keypair = makeKeypair();
  const chain = buildChain(keypair);
  assert.deepEqual(pinDelegationChainSigners(chain, undefined), { status: "not_checked", unpinned_links: [] });
  assert.deepEqual(pinDelegationChainSigners(chain, keypair.publicKeyPem), { status: "pinned", unpinned_links: [] });

  const otherKeypair = makeKeypair();
  const result = pinDelegationChainSigners(chain, otherKeypair.publicKeyPem);
  assert.equal(result.status, "not_pinned");
  assert.deepEqual(result.unpinned_links.sort(), chain.map((l) => l.delegation_id).sort());
});

// --- Policy-ref pinning ------------------------------------------------------------------------

test("pinPolicyRef: not_applicable without a policy_ref, not_checked without a pinned hash, pinned/not_pinned otherwise", () => {
  assert.deepEqual(pinPolicyRef(null, "abc"), { status: "not_applicable" });
  const policyRef = { policy_id: "review", version: 1, hash: "sha256:abc" };
  assert.deepEqual(pinPolicyRef(policyRef, undefined), { status: "not_checked" });
  assert.deepEqual(pinPolicyRef(policyRef, "sha256:abc"), { status: "pinned" });
  assert.deepEqual(pinPolicyRef(policyRef, "sha256:different"), { status: "not_pinned" });
});

// --- Governance provenance: build / summarize / live-derive --------------------------------

test("buildGovernanceProvenanceV1: field labels follow enforcement observation and counts", () => {
  const enforcement = [
    enforcementRecord({ record_id: "r1", observed_by: "enforcer" }),
    enforcementRecord({ record_id: "r2", observed_by: "enforcer" }),
  ];
  const provenance = buildGovernanceProvenanceV1({
    decisionsCount: 1, approvalsCount: 1, enforcement, policyRefPresent: true,
  });
  assert.equal(provenance.fields.enforcement, "enforcer_recorded");
  assert.equal(provenance.fields.constraints, "agent_reported");
  assert.equal(provenance.fields.actions, "verifier_checked");
  assert.equal(provenance.fields.decisions, "verifier_checked");
  assert.equal(provenance.fields.approvals, "agent_reported");
  assert.equal(provenance.events.length, 2);
  assert.deepEqual(provenance.events[0], { ref: "r1", label: "enforcer_recorded" });
});

test("buildGovernanceProvenanceV1: no enforcement/decisions/approvals/policy -> unobserved where applicable", () => {
  const provenance = buildGovernanceProvenanceV1({
    decisionsCount: 0, approvalsCount: 0, enforcement: [], policyRefPresent: false,
  });
  assert.equal(provenance.fields.enforcement, "unobserved");
  assert.equal(provenance.fields.constraints, "unobserved");
  assert.equal(provenance.fields.actions, "unobserved");
  assert.equal(provenance.fields.decisions, "unobserved");
  assert.equal(provenance.fields.approvals, "unobserved");
});

test("buildGovernanceProvenanceV1: mixed observed_by across enforcement records falls back to agent_reported", () => {
  const enforcement = [
    enforcementRecord({ record_id: "r1", observed_by: "enforcer" }),
    enforcementRecord({ record_id: "r2", observed_by: "observer" }),
  ];
  const provenance = buildGovernanceProvenanceV1({ decisionsCount: 0, approvalsCount: 0, enforcement, policyRefPresent: false });
  assert.equal(provenance.fields.enforcement, "agent_reported");
});

test("summarizeGovernanceProvenance: counts every field and event label, total is fields + events", () => {
  const provenance = buildGovernanceProvenanceV1({
    decisionsCount: 0, approvalsCount: 0, enforcement: [enforcementRecord({ observed_by: "observer" })], policyRefPresent: false,
  });
  const summary = summarizeGovernanceProvenance(provenance);
  assert.equal(summary.total, 12 + 1);
  assert.equal(summary.statement, "Self-reported compliance is not independently verified compliance.");
  const sumOfCounts = Object.values(summary.counts).reduce((a, b) => a + b, 0);
  assert.equal(sumOfCounts, summary.total);
});

test("deriveLiveGovernanceProvenanceV1: not_checked without a receipt or an undecided cross-check, discrepancy on failure, upgrade on success", () => {
  const provenance = buildGovernanceProvenanceV1({ decisionsCount: 0, approvalsCount: 0, enforcement: [], policyRefPresent: false });

  assert.deepEqual(
    deriveLiveGovernanceProvenanceV1(provenance, { observerReceiptPresent: false, observerConfirmed: null }),
    { status: "not_checked", upgraded_fields: [], discrepancies: [] },
  );
  assert.deepEqual(
    deriveLiveGovernanceProvenanceV1(provenance, { observerReceiptPresent: true, observerConfirmed: null }),
    { status: "not_checked", upgraded_fields: [], discrepancies: [] },
  );
  assert.deepEqual(
    deriveLiveGovernanceProvenanceV1(provenance, { observerReceiptPresent: true, observerConfirmed: false }),
    { status: "discrepancy", upgraded_fields: [], discrepancies: ["observer_receipt_present_but_cross_check_failed"] },
  );

  const result = deriveLiveGovernanceProvenanceV1(provenance, { observerReceiptPresent: true, observerConfirmed: true });
  assert.equal(result.status, "consistent");
  assert.deepEqual(result.discrepancies, []);
  assert.ok(result.upgraded_fields.includes("actor"));
});
