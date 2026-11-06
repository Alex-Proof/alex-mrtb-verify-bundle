import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { verifyRekorStapling, canonicalEvidenceJson, computeEffectiveRevokedAt, checkSignerNotRevokedAfterEvidenceTime } from "../dist/verify.js";

// Real, live access against the public Sigstore Rekor log -- deliberately NO mock. Every
// stapleTestRecord() call creates a PERMANENT, public Rekor log entry (transparency logs are
// immutable/undeletable) -- reason therefore carries a clearly recognizable test marker, in case
// the log is ever searched for this. The Ed25519 key used is freshly generated per test run and
// carries no production meaning.
const REKOR_BASE_URL = "https://rekor.sigstore.dev";

async function submitHashedRekordEcdsaOuter(artifact) {
  const ephemeral = generateKeyPairSync("ec", {
    namedCurve: "P-256",
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const signature = sign("sha256", artifact, ephemeral.privateKey);
  const hash = createHash("sha256").update(artifact).digest("hex");
  const res = await fetch(`${REKOR_BASE_URL}/api/v1/log/entries`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      kind: "hashedrekord",
      apiVersion: "0.0.1",
      spec: {
        data: { hash: { algorithm: "sha256", value: hash } },
        signature: { content: signature.toString("base64"), publicKey: { content: Buffer.from(ephemeral.publicKey, "utf8").toString("base64") } },
      },
    }),
  });
  if (!res.ok) throw new Error(`rekor submit failed: HTTP ${res.status} ${await res.text()}`);
  const json = await res.json();
  const uuid = Object.keys(json)[0];
  const raw = json[uuid];
  return {
    schema_version: "rekor-tlog-entry@1.0",
    entry_uuid: uuid,
    log_index: raw.logIndex,
    log_id: raw.logID,
    integrated_time: raw.integratedTime,
    body: raw.body,
    inclusion_proof: {
      log_index: raw.verification.inclusionProof.logIndex,
      root_hash: raw.verification.inclusionProof.rootHash,
      tree_size: raw.verification.inclusionProof.treeSize,
      hashes: raw.verification.inclusionProof.hashes,
      checkpoint: raw.verification.inclusionProof.checkpoint,
    },
    submitted_at: new Date().toISOString(),
  };
}

/** Replicates the production path (stapleRevocationToRekor() in the private source): self-
 *  attestation with the (here: freshly generated test) Ed25519 key, then submits the attested
 *  record as a hashedrekord with a disposable ECDSA key. */
async function stapleTestRecord(baseRecord, privateKeyPem) {
  const selfAttestationSignature = sign(null, Buffer.from(canonicalEvidenceJson(baseRecord), "utf8"), privateKeyPem).toString("base64");
  const attestedRecord = { ...baseRecord, self_attestation_signature: selfAttestationSignature };
  const entry = await submitHashedRekordEcdsaOuter(Buffer.from(canonicalEvidenceJson(attestedRecord), "utf8"));
  return { ...attestedRecord, rekor_tlog_entry: entry };
}

test("verifyRekorStapling: a real, freshly submitted entry is confirmed live against Rekor", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const baseRecord = {
    key_id: createHash("sha256").update(publicKey).digest("hex"),
    public_key_pem: publicKey,
    valid_from: "2026-01-01T00:00:00.000Z",
    revoked_at: new Date().toISOString(),
    reason: "TEST ENTRY -- automated alex-mrtb-verify-bundle rekor-stapling.test.mjs, safe to ignore",
    replaced_by: null,
  };
  const record = await stapleTestRecord(baseRecord, privateKey);

  const result = await verifyRekorStapling(record);
  assert.equal(result.ok, true, `expected ok, got reason=${result.reason}`);
});

test("verifyRekorStapling: rejects a record whose content was changed AFTER the Rekor submit", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const baseRecord = {
    key_id: createHash("sha256").update(publicKey).digest("hex"),
    public_key_pem: publicKey,
    valid_from: "2026-01-01T00:00:00.000Z",
    revoked_at: new Date().toISOString(),
    reason: "TEST ENTRY -- automated alex-mrtb-verify-bundle rekor-stapling.test.mjs, safe to ignore",
    replaced_by: null,
  };
  const record = await stapleTestRecord(baseRecord, privateKey);
  const tampered = { ...record, reason: "changed afterwards -- must no longer hold" };

  const result = await verifyRekorStapling(tampered);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "self_attestation_signature_invalid");
});

test("verifyRekorStapling: rejects a Rekor entry that belongs to a DIFFERENT record", async () => {
  const keyA = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const keyB = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const baseA = {
    key_id: createHash("sha256").update(keyA.publicKey).digest("hex"),
    public_key_pem: keyA.publicKey,
    valid_from: "2026-01-01T00:00:00.000Z",
    revoked_at: new Date().toISOString(),
    reason: "TEST ENTRY -- automated alex-mrtb-verify-bundle rekor-stapling.test.mjs, safe to ignore (record A)",
    replaced_by: null,
  };
  const baseB = {
    key_id: createHash("sha256").update(keyB.publicKey).digest("hex"),
    public_key_pem: keyB.publicKey,
    valid_from: "2026-01-01T00:00:00.000Z",
    revoked_at: new Date().toISOString(),
    reason: "TEST ENTRY -- automated alex-mrtb-verify-bundle rekor-stapling.test.mjs, safe to ignore (record B)",
    replaced_by: null,
  };
  const recordA = await stapleTestRecord(baseA, keyA.privateKey);
  const recordB = await stapleTestRecord(baseB, keyB.privateKey);
  // Rekor entry of B swapped onto the (otherwise validly self-attested) record A.
  const swapped = { ...recordA, rekor_tlog_entry: recordB.rekor_tlog_entry };

  const result = await verifyRekorStapling(swapped);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "rekor_body_hash_mismatch");
});

test("verifyRekorStapling: a missing rekor_tlog_entry is honestly reported as such", async () => {
  const result = await verifyRekorStapling({
    key_id: "abc", public_key_pem: "irrelevant", valid_from: "2026-01-01T00:00:00.000Z",
    revoked_at: "2026-01-02T00:00:00.000Z", reason: "irrelevant", replaced_by: null,
  });
  assert.deepEqual(result, { ok: false, reason: "no_rekor_tlog_entry" });
});

// 06.11.2026 (SaSame/DM challenge: revoked_at is self-attested, a compromised key can backdate
// its own revocation). computeEffectiveRevokedAt() takes max(revoked_at, integrated_time) --
// Rekor's time cannot be chosen by the key holder.
test("computeEffectiveRevokedAt: returns integrated_time, not a backdated revoked_at, when integrated_time is later", () => {
  const backdatedRevokedAt = "2020-01-01T00:00:00.000Z";
  const laterIntegratedTimeSeconds = Math.floor(Date.parse("2026-11-06T00:00:00.000Z") / 1000);
  const record = {
    key_id: "irrelevant", public_key_pem: "irrelevant", valid_from: "2019-01-01T00:00:00.000Z",
    revoked_at: backdatedRevokedAt, reason: "test", replaced_by: null,
    rekor_tlog_entry: {
      schema_version: "rekor-tlog-entry@1.0", entry_uuid: "x", log_index: 1, log_id: "x",
      integrated_time: laterIntegratedTimeSeconds, body: "x",
      inclusion_proof: { log_index: 1, root_hash: "x", tree_size: 1, hashes: [], checkpoint: "x" },
      submitted_at: new Date().toISOString(),
    },
  };
  const effective = computeEffectiveRevokedAt(record);
  assert.equal(effective, new Date(laterIntegratedTimeSeconds * 1000).toISOString());
  assert.notEqual(effective, backdatedRevokedAt);
});

test("computeEffectiveRevokedAt: stays at revoked_at when there is no rekor_tlog_entry (pre-existing, unhardened behavior)", () => {
  const record = {
    key_id: "irrelevant", public_key_pem: "irrelevant", valid_from: "2019-01-01T00:00:00.000Z",
    revoked_at: "2026-01-01T00:00:00.000Z", reason: "test", replaced_by: null,
  };
  assert.equal(computeEffectiveRevokedAt(record), record.revoked_at);
});

// DoD: a forged or missing inclusion proof must be recognized as unverified, never as "probably
// fine" -- checkSignerNotRevokedAfterEvidenceTime() must never fail-open on a broken
// rekor_tlog_entry.
test("checkSignerNotRevokedAfterEvidenceTime: lets a key through when it has no revocation record at all", async () => {
  const consensus = {
    purpose: "evidence_package", channels: [], agreed_key_id: "some-key",
    agreed_public_key_pem: "irrelevant", agreement_count: 1, total_channels: 1, divergent: false,
    revocations: [],
  };
  const result = await checkSignerNotRevokedAfterEvidenceTime(consensus, null);
  assert.deepEqual(result, { ok: true });
});

test("checkSignerNotRevokedAfterEvidenceTime: rejects a record with a forged (unverifiable) rekor_tlog_entry instead of failing open", async () => {
  const { publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const record = {
    key_id: "revoked-key", public_key_pem: publicKey, valid_from: "2019-01-01T00:00:00.000Z",
    revoked_at: "2020-01-01T00:00:00.000Z", reason: "test", replaced_by: null,
    self_attestation_signature: "ZmFrZQ==",
    rekor_tlog_entry: {
      schema_version: "rekor-tlog-entry@1.0", entry_uuid: "fake", log_index: 1, log_id: "fake",
      integrated_time: Math.floor(Date.now() / 1000), body: Buffer.from(JSON.stringify({ kind: "hashedrekord" })).toString("base64"),
      inclusion_proof: { log_index: 1, root_hash: "fake", tree_size: 1, hashes: [], checkpoint: "fake" },
      submitted_at: new Date().toISOString(),
    },
  };
  const consensus = {
    purpose: "evidence_package", channels: [], agreed_key_id: "revoked-key",
    agreed_public_key_pem: "irrelevant", agreement_count: 1, total_channels: 1, divergent: false,
    revocations: [record],
  };
  const result = await checkSignerNotRevokedAfterEvidenceTime(consensus, null);
  assert.equal(result.ok, false);
  assert.match(result.reason, /^revocation_proof_invalid_/);
});

test("checkSignerNotRevokedAfterEvidenceTime: blocks evidence whose timestamp is after the effective revocation (no rekor_tlog_entry)", async () => {
  const record = {
    key_id: "revoked-key", public_key_pem: "irrelevant", valid_from: "2019-01-01T00:00:00.000Z",
    revoked_at: "2026-01-01T00:00:00.000Z", reason: "test", replaced_by: null,
  };
  const consensus = {
    purpose: "evidence_package", channels: [], agreed_key_id: "revoked-key",
    agreed_public_key_pem: "irrelevant", agreement_count: 1, total_channels: 1, divergent: false,
    revocations: [record],
  };
  const result = await checkSignerNotRevokedAfterEvidenceTime(consensus, "2026-06-01T00:00:00.000Z");
  assert.deepEqual(result, { ok: false, reason: "signer_key_revoked_before_evidence_time" });
});

test("checkSignerNotRevokedAfterEvidenceTime: without an evidence timestamp, no time comparison is possible and it honestly lets it through", async () => {
  const record = {
    key_id: "revoked-key", public_key_pem: "irrelevant", valid_from: "2019-01-01T00:00:00.000Z",
    revoked_at: "2020-01-01T00:00:00.000Z", reason: "test", replaced_by: null,
  };
  const consensus = {
    purpose: "evidence_package", channels: [], agreed_key_id: "revoked-key",
    agreed_public_key_pem: "irrelevant", agreement_count: 1, total_channels: 1, divergent: false,
    revocations: [record],
  };
  const result = await checkSignerNotRevokedAfterEvidenceTime(consensus, null);
  assert.deepEqual(result, { ok: true });
});
