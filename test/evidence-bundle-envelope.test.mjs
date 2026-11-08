import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateEvidenceBundleEnvelope } from "../dist/verify.js";

// 08.11.2026 (Mirror-Sync-Nachtrag, Memory evidence_bundle_envelope_fuzz_test): strikte
// Huellen-Pruefung VOR jeder Krypto-/Trace-Logik -- besonders relevant fuer dieses Paket, da
// verifyBundleObject() hier von Downstream-Konsumenten direkt mit UNTRUSTED Netzwerk-Input
// aufgerufen wird. Ausgangspunkt ist ein echtes, produktionsidentisch signiertes Bundle, keine
// Mock-Struktur.

const BASE_BUNDLE = JSON.parse(
  readFileSync(fileURLToPath(new URL("../bundle-real-run_1787366396912.json", import.meta.url)), "utf8"),
);

const REQUIRED_FIELDS = [
  "bundle_id", "capability", "run_id", "claim_ladder", "executed_at",
  "trace_events", "trace_hash_chain", "outcome", "signature", "public_key",
];

function clone() {
  return JSON.parse(JSON.stringify(BASE_BUNDLE));
}

test("valides Bundle passiert das Huellen-Gate unveraendert (ok:true)", () => {
  assert.equal(validateEvidenceBundleEnvelope(clone()).ok, true);
});

for (const field of REQUIRED_FIELDS) {
  test(`fehlendes Pflichtfeld '${field}' -> ok:false, kein Crash`, () => {
    const mutated = clone();
    delete mutated[field];
    assert.doesNotThrow(() => {
      assert.equal(validateEvidenceBundleEnvelope(mutated).ok, false);
    });
  });
}

// trace_events/trace_hash_chain sind Array-of-string -- ein leeres Array ist dort GUELTIG (kein
// falscher Typ), deshalb getrennt von den reinen String-Feldern behandelt.
const WRONG_TYPE_FOR_STRING_FIELD = [42, true, null, [], {}, ["x", "y"]];
const WRONG_TYPE_FOR_ARRAY_FIELD = ["x", 42, true, null, {}, [1, 2]];
const STRING_FIELDS = REQUIRED_FIELDS.filter((f) => !["trace_events", "trace_hash_chain"].includes(f));
const ARRAY_FIELDS = ["trace_events", "trace_hash_chain"];

for (const field of STRING_FIELDS) {
  for (const wrongValue of WRONG_TYPE_FOR_STRING_FIELD) {
    test(`Feld '${field}' = ${JSON.stringify(wrongValue)} (falscher Typ) -> ok:false, kein Crash`, () => {
      const mutated = clone();
      mutated[field] = wrongValue;
      assert.doesNotThrow(() => {
        assert.equal(validateEvidenceBundleEnvelope(mutated).ok, false);
      });
    });
  }
}

for (const field of ARRAY_FIELDS) {
  for (const wrongValue of WRONG_TYPE_FOR_ARRAY_FIELD) {
    test(`Feld '${field}' = ${JSON.stringify(wrongValue)} (falscher Typ) -> ok:false, kein Crash`, () => {
      const mutated = clone();
      mutated[field] = wrongValue;
      assert.doesNotThrow(() => {
        assert.equal(validateEvidenceBundleEnvelope(mutated).ok, false);
      });
    });
  }
}

test("unbekanntes Top-Level-Feld -> ok:false (strictObject)", () => {
  const mutated = clone();
  mutated.totally_unknown_field = "irrelevant";
  assert.equal(validateEvidenceBundleEnvelope(mutated).ok, false);
});

for (const typo of ["bundle_Id", "Capability", "run_id ", "outcome2", "signature_"]) {
  test(`Tippfehler-Feldname '${typo}' -> ok:false`, () => {
    const mutated = clone();
    mutated[typo] = "irrelevant";
    assert.equal(validateEvidenceBundleEnvelope(mutated).ok, false);
  });
}

const BAD_APPROVAL_VARIANTS = [0, 1, "true", "false", [], {}];
for (const value of BAD_APPROVAL_VARIANTS) {
  test(`approval_attestation_required = ${JSON.stringify(value)} (nicht Boolean) -> ok:false`, () => {
    const mutated = clone();
    mutated.approval_attestation_required = value;
    assert.equal(validateEvidenceBundleEnvelope(mutated).ok, false);
  });
}

const TOP_LEVEL_MUTATIONS = [
  ["Array statt Objekt", [BASE_BUNDLE]],
  ["String", "nicht ein bundle"],
  ["Zahl", 42],
  ["null", null],
  ["undefined", undefined],
  ["leeres Objekt", {}],
];
for (const [label, value] of TOP_LEVEL_MUTATIONS) {
  test(`Top-Level = ${label} -> ok:false, kein Crash`, () => {
    assert.doesNotThrow(() => {
      assert.equal(validateEvidenceBundleEnvelope(value).ok, false);
    });
  });
}

const WEIRD_STRINGS = ["\u{1F600}\u{1F680}", "\u0000", "a\u0000b", "\uD800", "\uDC00", "𐀀"];
for (const weird of WEIRD_STRINGS) {
  test(`bundle_id = ${JSON.stringify(weird)} (Emoji/Surrogat/Null-Byte) -> kein Crash`, () => {
    const mutated = clone();
    mutated.bundle_id = weird;
    assert.doesNotThrow(() => validateEvidenceBundleEnvelope(mutated));
  });
}

test("Rauschen in customer_evidence (unmodellierte Tiefe) -> ok bleibt true (kein Fund, Gate prueft bewusst nicht die Tiefe)", () => {
  const mutated = clone();
  mutated.customer_evidence = { anything: { nested: [1, 2, { deep: true }] } };
  assert.equal(validateEvidenceBundleEnvelope(mutated).ok, true);
});
