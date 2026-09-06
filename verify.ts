import { createHash, verify, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { AsnSerializer, AsnParser, OctetString } from "@peculiar/asn1-schema";
import { ContentInfo, SignedData, SignerInfo, id_messageDigest } from "@peculiar/asn1-cms";

type ClaimLadder = "L0" | "L1" | "L2" | "L3" | "L4";

export interface ValidationAttestationV1 {
  schema_version: "validation-attestation@1.0"; producer: "independent_evidence_runner"; repository_commit: string;
  environment: Record<string, unknown>; environment_sha256: string; started_at: string; completed_at: string; duration_ms: number;
  exit_code: number; passed: boolean; stdout_sha256: string; stderr_sha256: string; report_sha256: string;
  signer_key_id: string; public_key: string; signature: string;
}

export interface ReviewerAttestationV1 {
  schema_version: "reviewer-attestation@1.0"; reviewer_id: string; decision: "approved" | "rejected"; reviewed_at: string;
  bundle_sha256: string; validation_attestation_sha256: string; reviewer_key_id: string; public_key: string; signature: string;
}

// 01.09.2026: identischer Fix wie server/services/mrtb/evidenceBundle.server.ts (kein Shared
// Import zwischen Server und diesem eigenstaendigen Verifier, siehe Datei-Header) -- ein
// schema_version-Wert ausserhalb dieser Menge liess die Trust-Anchor-Pruefung komplett
// uebersprungen werden, die Signaturpruefung darunter verifizierte dann nur noch gegen den im
// Bundle selbst mitgelieferten public_key. Bei jeder Aenderung hier: identische Aenderung auch in
// evidenceBundle.server.ts, sonst laeuft dieser oeffentliche Verifier wieder auseinander.
const DEVTASK_V2_SCHEMA_VERSIONS = new Set(["evidence-package@2.0", "evidence-package@2.1", "evidence-package@2.2"]);
const DEVTASK_EVIDENCE_SPEC_VERSION = "devtask.execution@1.0" as const;
function isDevTaskV2Schema(v: string | undefined): boolean {
  return v !== undefined && DEVTASK_V2_SCHEMA_VERSIONS.has(v);
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function canonicalEvidenceJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalEvidenceJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().filter(key => record[key] !== undefined)
      .map(key => `${JSON.stringify(key)}:${canonicalEvidenceJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }

export function verifyValidationAttestation(attestation: ValidationAttestationV1, trustedPublicKey: string, expectedCommit: string): { ok: boolean; reason?: string } {
  const { signature, public_key, signer_key_id, ...payload } = attestation;
  if (public_key !== trustedPublicKey || signer_key_id !== `ed25519:${sha256(trustedPublicKey)}`) return { ok: false, reason: "untrusted_evidence_runner" };
  if (attestation.schema_version !== "validation-attestation@1.0" || attestation.repository_commit !== expectedCommit) return { ok: false, reason: "validation_scope_mismatch" };
  if (attestation.environment_sha256 !== sha256(canonical(attestation.environment))) return { ok: false, reason: "environment_hash_mismatch" };
  if (![attestation.stdout_sha256, attestation.stderr_sha256, attestation.report_sha256].every(h => /^[a-f0-9]{64}$/.test(h))) return { ok: false, reason: "invalid_report_hash" };
  if (!verify(null, Buffer.from(canonical(payload)), public_key, Buffer.from(signature, "base64"))) return { ok: false, reason: "invalid_validation_signature" };
  if (!attestation.passed || attestation.exit_code !== 0) return { ok: false, reason: "validation_failed" };
  return { ok: true };
}

export function verifyReviewerAttestation(attestation: ReviewerAttestationV1, trustedPublicKey: string, bundleBytes: Buffer, validationBytes: Buffer): { ok: boolean; reason?: string } {
  const { signature, public_key, reviewer_key_id, ...payload } = attestation;
  if (public_key !== trustedPublicKey || reviewer_key_id !== `ed25519:${sha256(trustedPublicKey)}`) return { ok: false, reason: "untrusted_reviewer" };
  if (attestation.bundle_sha256 !== sha256(bundleBytes) || attestation.validation_attestation_sha256 !== sha256(validationBytes)) return { ok: false, reason: "review_scope_mismatch" };
  if (!verify(null, Buffer.from(canonical(payload)), public_key, Buffer.from(signature, "base64"))) return { ok: false, reason: "invalid_reviewer_signature" };
  if (attestation.decision !== "approved") return { ok: false, reason: "review_rejected" };
  return { ok: true };
}

/** 29.08.2026: RFC-3161-Zeitstempel ueber den kompletten signierten Bundle-Inhalt, best-effort
 *  von einer oeffentlichen TSA angehaengt (siehe rfc3161Timestamp.server.ts im Alex-Monorepo,
 *  identische Definition hier). Seit 05.09.2026 prueft dieser Verifier sowohl die Hash-Bindung
 *  (verifyRfc3161Binding()) als auch die CMS-Signatur der TSA und deren Zertifikatskette gegen
 *  die gepinnte FreeTSA-Root-CA (verifyRfc3161TsaChain()). Das rohe `token_der_base64` bleibt
 *  zusaetzlich Standard-RFC-3161-DER, unabhaengig mit externen Werkzeugen pruefbar. */
export interface Rfc3161Timestamp {
  schema_version: "rfc3161-timestamp@1.0";
  tsa_url: string;
  timestamped_sha256: string;
  gen_time: string;
  token_der_base64: string;
}

export interface EvidenceBundle {
  schema_version?: "evidence-package@2.0" | "evidence-package@2.1" | "evidence-package@2.2";
  spec_version?: typeof DEVTASK_EVIDENCE_SPEC_VERSION;
  bundle_id: string;
  capability: string;
  run_id: string;
  claim_ladder: ClaimLadder;
  executed_at: string;
  trace_events: string[];
  trace_hash_chain: string[];
  outcome: "verified" | "failed" | "inconclusive";
  // 01.09.2026: evidence-package@2.1, Teil der signierten Nutzlast (siehe Kommentar bei
  // CustomerEvidenceV1 oben und dem Zwilling in evidenceBundle.server.ts).
  customer_evidence?: CustomerEvidenceV1;
  signature: string;
  public_key: string;
  signer_key_id?: string;
  controller_evidence?: DevTaskControllerEvidenceV2;
  required_evidence?: string[];
  rfc3161_timestamp?: Rfc3161Timestamp;
  approval_attestation_required?: boolean;
  approval_attestation?: ApprovalAttestationV1;
  // 05.09.2026 (Bauanleitung Evidence-Hardening Phase 2, Baustein 2): identisches Muster wie
  // rfc3161_timestamp -- erst nach dem Signieren best-effort angehaengt, kein Teil der
  // Ed25519-Signaturnutzlast. Identische Definition zu observerRelay.server.ts im Alex-Monorepo.
  observer_receipt?: ObserverReceipt;
}

export interface ObserverReceipt {
  schema_version: "observer-receipt@1.0";
  observer_url: string;
  leaf_index: number;
  received_at: string;
}

export interface ApprovalAttestationV1 {
  schema_version: "approval-attestation@1.0"; actor_id: string; approved_at: string; bundle_sha256: string;
  signer_key_id: string; public_key: string; signature: string;
}

/** Prueft nur, dass ein vorhandener Zeitstempel wirklich zu DIESEM Bundle-Inhalt gehoert
 *  (Hash-Uebereinstimmung) -- kein Ersatz fuer die eigentliche Signaturpruefung.
 *
 *  31.08.2026 (live gefunden): der Zeitstempel wird server-seitig VOR der Freigabe-Attestation
 *  angehaengt, der gehashte Stand kannte approval_attestation also noch nicht -- ohne diesen
 *  Ausschluss schlaegt die Bindung bei jedem freigegebenen Bundle deterministisch fehl. Gleiches
 *  Muster wie die Signaturpruefung weiter unten.
 *
 *  06.09.2026 (identischer Fix wie rfc3161Timestamp.server.ts, live gefunden beim Bau der
 *  Proof-Policy-Gate-Tests, Punkt 3): observer_receipt wird ebenfalls erst NACH dem Zeitstempel
 *  angehaengt (attachRfc3161Timestamp -> attachApprovalAttestation -> attachObserverReceipt) und
 *  fehlte hier bisher im Ausschluss -- seit Einfuehrung von observer_receipt (05.09.2026) scheiterte
 *  die Bindung bei jedem zusaetzlich vom Observer bezeugten Bundle deterministisch. */
export function verifyRfc3161Binding(bundle: EvidenceBundle): { ok: boolean; reason?: string } {
  if (!bundle.rfc3161_timestamp) return { ok: false, reason: "no_timestamp_present" };
  const { rfc3161_timestamp, approval_attestation, observer_receipt, ...withoutTimestamp } = bundle;
  const recomputed = sha256(JSON.stringify(withoutTimestamp));
  if (recomputed !== rfc3161_timestamp.timestamped_sha256) return { ok: false, reason: "timestamp_hash_mismatch" };
  return { ok: true };
}

// Gepinntes FreeTSA-Root-CA-Zertifikat (https://freetsa.org/files/cacert.pem), identisch zu
// server/services/mrtb/rfc3161Timestamp.server.ts im Alex-Monorepo (kein Shared Import zwischen
// Server und diesem eigenstaendigen Verifier, siehe Datei-Header). Per `curl`+`openssl x509
// -fingerprint -sha256` am 05.09.2026 gegengeprueft: SHA-256-Fingerabdruck
// A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC,
// gueltig bis 2041-03-07.
const FREETSA_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql
mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx
0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel
b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm
q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V
DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd
EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3
SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT
FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB
BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837
gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq
M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD
AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/
gBT6VQ2MNGZRQ0z357OnbJWveuakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU
U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi
MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl
cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw
MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh
LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB
FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB
BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG
CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh
cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC
AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt
nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF
ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7
gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz
aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ
DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4
1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW
99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb
8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb
Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA
I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=
-----END CERTIFICATE-----`;

const DIGEST_OID_TO_NODE_HASH: Record<string, string> = {
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
};

function normalizeSerialHex(buf: ArrayBuffer): string {
  let bytes = Buffer.from(buf);
  while (bytes.length > 1 && bytes[0] === 0x00) bytes = bytes.subarray(1);
  return bytes.toString("hex").toUpperCase();
}

function findSignerCertificateDer(signedData: SignedData, signerInfo: SignerInfo): Buffer | null {
  const wanted = signerInfo.sid?.issuerAndSerialNumber;
  if (!wanted || !signedData.certificates) return null;
  const wantedSerialHex = normalizeSerialHex(wanted.serialNumber);
  for (const choice of signedData.certificates) {
    if (!choice.certificate) continue;
    let der: Buffer;
    try { der = Buffer.from(AsnSerializer.serialize(choice.certificate)); } catch { continue; }
    try {
      if (new X509Certificate(der).serialNumber.toUpperCase() === wantedSerialHex) return der;
    } catch { /* kein gueltiges X.509 -- naechsten Kandidaten pruefen */ }
  }
  return null;
}

function encodeDerLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** RFC 5652 §5.4: signedAttrs sind im Token als IMPLICIT [0] SET codiert, fuer die Signatur-
 *  pruefung aber als EXPLIZITES "SET OF" (Tag 0x31, UNIVERSAL) zu behandeln. `@peculiar/asn1-
 *  schema` befuellt das dafuer eigentlich vorgesehene `signedAttrsRaw`-Feld bei `repeated`-
 *  Properties wie diesem NICHT (Bibliotheks-Einschraenkung) -- deshalb Nachbau aus den bereits
 *  geparsten Attribut-Objekten statt aus diesem Feld. Empirisch mit einem echten FreeTSA-Token
 *  bestaetigt (05.09.2026), identisches Vorgehen wie im Server-Original. */
function reencodeSignedAttrsForVerification(signedAttrs: SignerInfo["signedAttrs"]): Buffer {
  const content = Buffer.concat((signedAttrs ?? []).map((attr) => Buffer.from(AsnSerializer.serialize(attr))));
  return Buffer.concat([Buffer.from([0x31]), encodeDerLength(content.length), content]);
}

/** Prueft, was verifyRfc3161Binding() bewusst offen laesst: dass der Zeitstempel-Token
 *  tatsaechlich von FreeTSA signiert wurde (CMS-SignerInfo-Signatur) UND dass das dafuer
 *  verwendete Zertifikat von der gepinnten FreeTSA-Root-CA ausgestellt ist. Keine Sperrlisten/
 *  OCSP-Pruefung. Identische Logik wie server/services/mrtb/rfc3161Timestamp.server.ts. */
export function verifyRfc3161TsaChain(timestamp: Rfc3161Timestamp): { ok: boolean; reason?: string } {
  try {
    const tokenDer = Buffer.from(timestamp.token_der_base64, "base64");
    const contentInfo = AsnParser.parse(tokenDer, ContentInfo);
    const signedData = AsnParser.parse(new Uint8Array(contentInfo.content), SignedData);
    const signerInfo = signedData.signerInfos[0];
    if (!signerInfo) return { ok: false, reason: "no_signer_info" };

    const certDer = findSignerCertificateDer(signedData, signerInfo);
    if (!certDer) return { ok: false, reason: "signer_certificate_not_found" };

    let tsaCert: X509Certificate;
    let rootCert: X509Certificate;
    try {
      tsaCert = new X509Certificate(certDer);
      rootCert = new X509Certificate(FREETSA_ROOT_CA_PEM);
    } catch {
      return { ok: false, reason: "certificate_unparsable" };
    }
    if (!tsaCert.verify(rootCert.publicKey)) return { ok: false, reason: "chain_untrusted" };

    const hashName = DIGEST_OID_TO_NODE_HASH[signerInfo.digestAlgorithm.algorithm];
    if (!hashName) return { ok: false, reason: "unsupported_digest_algorithm" };

    const tstInfoOctets = signedData.encapContentInfo.eContent?.single;
    if (!tstInfoOctets) return { ok: false, reason: "no_encapsulated_content" };
    const tstInfoBytes = Buffer.from(tstInfoOctets.buffer);

    if (!signerInfo.signedAttrs || signerInfo.signedAttrs.length === 0) {
      const sigOk = verify(hashName, tstInfoBytes, tsaCert.publicKey, Buffer.from(signerInfo.signature.buffer));
      return sigOk ? { ok: true } : { ok: false, reason: "signature_invalid" };
    }

    const messageDigestAttr = signerInfo.signedAttrs.find((a) => a.attrType === id_messageDigest);
    if (!messageDigestAttr?.attrValues[0]) return { ok: false, reason: "no_message_digest_attribute" };
    const claimedDigest = Buffer.from(AsnParser.parse(messageDigestAttr.attrValues[0], OctetString).buffer);
    const actualDigest = createHash(hashName).update(tstInfoBytes).digest();
    if (!claimedDigest.equals(actualDigest)) return { ok: false, reason: "message_digest_mismatch" };

    const reencodedAttrs = reencodeSignedAttrsForVerification(signerInfo.signedAttrs);
    const sigOk = verify(hashName, reencodedAttrs, tsaCert.publicKey, Buffer.from(signerInfo.signature.buffer));
    return sigOk ? { ok: true } : { ok: false, reason: "signature_invalid" };
  } catch (e: any) {
    return { ok: false, reason: `parse_error:${e?.message ?? "unknown"}` };
  }
}

interface DevTaskControllerEvidenceV2 {
  /** Frozen contract, additive; checked against the signed contract-bound event. */
  contract_snapshot?: Record<string, unknown> | null;
  producer: "privileged_controller";
  task_id: string;
  attempt_number: number;
  base_commit: string | null;
  result_reference: string | null;
  diff_stat_sha256: string | null;
  diff_full: string | null;
  diff_full_sha256: string | null;
  execution_reference: string | null;
  validation_reference: string | null;
  approval_reference: string | null;
  sandbox_reference: string | null;
  sandbox_attestation: SandboxAttestationV2 | null;
  agent_run_id: string | null;
  repository_state?: RepositoryStateEvidenceV1 | null;
  test_integrity_policy?: TestIntegrityPolicyEvidenceV1;
}

interface TestIntegrityPolicyEvidenceV1 {
  schema_version: "test-integrity-policy@1.0";
  policy: "protect_existing_tests";
  protected: boolean;
  status: "passed" | "failed" | "not_requested" | "inconclusive";
  violating_files: string[];
}

function isProtectedTestPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  return /(^|\/)(__tests__|tests?|specs?)(\/|$)/.test(normalized) ||
    /\.(test|spec)\.[^/]+$/.test(normalized) ||
    /(^|\/)(vitest|jest|playwright|cypress)\.config\.[^/]+$/.test(normalized);
}

function buildTestIntegrityPolicyEvidence(
  protectedExistingTests: boolean,
  repository: RepositoryStateEvidenceV1 | null | undefined,
): TestIntegrityPolicyEvidenceV1 {
  if (!protectedExistingTests) return {
    schema_version: "test-integrity-policy@1.0", policy: "protect_existing_tests",
    protected: false, status: "not_requested", violating_files: [],
  };
  if (!repository) return {
    schema_version: "test-integrity-policy@1.0", policy: "protect_existing_tests",
    protected: true, status: "inconclusive", violating_files: [],
  };
  const violatingFiles = repository.changed_files
    .filter(file => file.status !== "A" && isProtectedTestPath(file.path))
    .map(file => file.path)
    .sort();
  return {
    schema_version: "test-integrity-policy@1.0", policy: "protect_existing_tests",
    protected: true, status: violatingFiles.length > 0 ? "failed" : "passed",
    violating_files: violatingFiles,
  };
}

// 01.09.2026: evidence-package@2.1 -- identische Kopie von
// server/services/mrtb/evidenceBundle.server.ts (kein Shared Import zwischen Server und diesem
// eigenstaendigen Verifier, siehe Datei-Header). buildCustomerSummaryDe() MUSS bei jeder
// Aenderung wortgleich auf beiden Seiten gehalten werden -- eine Abweichung (z.B. ein
// Rundungsfix nur hier) laesst jedes 2.1-Bundle mit customer_summary_mismatch scheitern.
interface CustomerTaskBriefV1 {
  title: string;
  raw_text: string;
}

interface CustomerCostPartialV1 {
  cost_usd: number | null;
  cost_usd_tracked: boolean;
  turns_used: number | null;
  duration_seconds: number | null;
  assigned_model: string | null;
  assigned_engine: string;
  token_tracking: "not_available";
}

interface CustomerDeniedActionV1 {
  path: string;
  reason: string;
}

interface CustomerApprovalV1 {
  proven: boolean;
  actor_id: string | null;
  channel: string;
  confirmed_by: string | null;
  confirmed_at: string | null;
  approved_at: string | null;
  approval_reference: string | null;
}

interface CustomerOpenRiskV1 {
  code: string;
  description: string;
  // Nicht Teil von buildCustomerSummaryDe()/customer_summary -- reine strukturierte Zusatzinfo,
  // hier nur fuer Typ-Konsistenz mit evidenceBundle.server.ts mitgefuehrt.
  recommended_action: string;
}

// 05.09.2026 (Bauanleitung "Geschichtete Evidence-Architektur" Punkt 1): identische Kopie von
// evidenceBundle.server.ts. satisfied: null = kein assertion-Feld gesetzt (Freitext, nicht
// maschinell pruefbar).
interface AcceptanceAssertionResult { description: string; satisfied: boolean | null }

interface CustomerEvidenceV1 {
  schema_version: "customer-evidence@1.0";
  brief: CustomerTaskBriefV1;
  cost_partial: CustomerCostPartialV1;
  denied: CustomerDeniedActionV1[];
  approval: CustomerApprovalV1;
  open_risks?: CustomerOpenRiskV1[];
  acceptance_assertions?: AcceptanceAssertionResult[];
  customer_summary: string;
}

function formatUsdDeterministic(amount: number): string {
  return `$${amount.toFixed(2)}`;
}
function formatDurationDeterministic(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}m ${s}s`;
}

type CustomerEvidenceInputV1 = Pick<CustomerEvidenceV1, "brief" | "cost_partial" | "denied" | "approval" | "open_risks" | "acceptance_assertions">;

function buildCustomerSummaryDe(input: CustomerEvidenceInputV1): string {
  const lines: string[] = [];
  lines.push(input.brief.title);
  lines.push("");
  lines.push("Auftrag:");
  lines.push(input.brief.raw_text);
  lines.push("");
  lines.push("Kosten:");
  if (input.cost_partial.cost_usd_tracked && input.cost_partial.cost_usd !== null) {
    const parts = [formatUsdDeterministic(input.cost_partial.cost_usd)];
    if (input.cost_partial.turns_used !== null) parts.push(`${input.cost_partial.turns_used} Turns`);
    if (input.cost_partial.duration_seconds !== null) parts.push(formatDurationDeterministic(input.cost_partial.duration_seconds));
    lines.push(parts.join(", "));
  } else {
    lines.push(`Kosten nicht erfasst (externe CLI-Engine \`${input.cost_partial.assigned_engine}\`, kein Kostentracking für diesen Pfad).`);
  }
  lines.push("Es werden ausschließlich Aggregatkosten erfasst, keine Tokenzahlen.");
  lines.push("");
  lines.push("Freigabe:");
  if (input.approval.actor_id === null) {
    lines.push("Keine Freigabe protokolliert.");
  } else if (input.approval.proven) {
    lines.push(`Bewiesen freigegeben über Kanal \`${input.approval.channel}\`.`);
  } else {
    lines.push(`Freigegeben über Kanal \`${input.approval.channel}\`, Identität nicht unabhängig bewiesen.`);
  }
  if (input.approval.confirmed_by !== null) lines.push(`Bestätigt von: ${input.approval.confirmed_by}`);
  if (input.approval.confirmed_at !== null) lines.push(`Bestätigt am: ${input.approval.confirmed_at}`);
  lines.push("");
  lines.push("Abgelehnte Aktionen:");
  if (input.denied.length === 0) {
    lines.push("Keine abgelehnten Aktionen in diesem Lauf.");
  } else {
    const sorted = [...input.denied].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    for (const d of sorted) lines.push(`- ${d.path} (${d.reason})`);
  }
  const openRisks = input.open_risks ?? [];
  if (openRisks.length > 0 || input.open_risks !== undefined) {
    lines.push("");
    lines.push("Offene Risiken:");
    if (openRisks.length === 0) {
      lines.push("Keine bekannten offenen Risiken erfasst.");
    } else {
      const sortedRisks = [...openRisks].sort((a, b) => (a.code < b.code ? -1 : a.code > b.code ? 1 : 0));
      for (const r of sortedRisks) lines.push(`- ${r.description}`);
    }
  }
  if (input.acceptance_assertions !== undefined) {
    lines.push("");
    lines.push("Erfolgskriterien:");
    const checkable = input.acceptance_assertions.filter(a => a.satisfied !== null);
    const satisfiedCount = checkable.filter(a => a.satisfied === true).length;
    if (input.acceptance_assertions.length === 0) {
      lines.push("Keine typisierten Erfolgskriterien fuer diesen Auftrag definiert.");
    } else {
      lines.push(`${satisfiedCount}/${checkable.length} maschinell pruefbare Kriterien erfuellt.`);
      const unmet = checkable.filter(a => a.satisfied === false);
      for (const a of unmet) lines.push(`- NICHT erfuellt: ${a.description}`);
      const freetext = input.acceptance_assertions.length - checkable.length;
      if (freetext > 0) lines.push(`${freetext} weitere(s) Kriterium/Kriterien nicht maschinell pruefbar (Freitext).`);
    }
  }
  return lines.join("\n");
}

interface RepositoryStateEvidenceV1 {
  schema_version: "repository-state@1.0"; base_commit: string; result_commit: string;
  tree_before_sha256: string; tree_after_sha256: string;
  changed_files: Array<{ path: string; status: "A" | "M" | "D"; before_sha256: string | null; after_sha256: string | null }>;
}

interface NetworkCaptureEvidenceV1 {
  schema_version: "egress-capture@1.0"; dns_queries_sha256: string; connections_sha256: string;
  connection_count: number; capture_incomplete: boolean;
}

interface SandboxAttestationV2 {
  schema_version: "sandbox-attestation@2.0"; sandbox_id: string; agent_id: string;
  started_at: string; completed_at: string; snapshot_sha256: string; policy_sha256: string;
  os_isolation_available: boolean; git_metadata_absent: boolean; controller_checkout_separated: boolean;
  network_policy: "bubblewrap_unshare_net_fail_closed" | "netns_egress_logged_v1" | "netns_egress_allowlisted_v1"; environment_policy: "bubblewrap_clearenv";
  process_policy: "systemd_scope_limits_and_kill"; handoff_manifest_sha256: string; rejected_manifest_sha256: string;
  network_capture: NetworkCaptureEvidenceV1 | null;
}

const SANDBOX_ATTESTATION_POLICY_NO_NETWORK = {
  schema_version: "sandbox-attestation@2.0", filesystem: "snapshot_without_git_or_symlinks",
  network: "bubblewrap_unshare_net_fail_closed", environment: "bubblewrap_clearenv",
  process: "systemd_scope_limits_and_kill", handoff: "regular_files_only_filtered",
};

// 29.08.2026 ("Code-Pruefstand"): zweites Profil, echtes Netzwerk + Verbindungsmitschnitt statt
// --unshare-net. Identische Ergaenzung wie in server/services/agentSandbox.server.ts und
// server/services/mrtb/evidenceBundle.server.ts -- bewusst von Hand dupliziert, kein Shared Import
// zwischen Server und diesem eigenstaendigen Verifier (siehe Datei-Header oben).
const SANDBOX_ATTESTATION_POLICY_NETWORK_CAPTURE = {
  ...SANDBOX_ATTESTATION_POLICY_NO_NETWORK,
  network: "netns_egress_logged_v1" as const,
};

// 29.08.2026 ("Code-Pruefstand" Phase C): drittes Profil, DURCHGESETZTE Allowlist statt reinem
// Mitschnitt. 05.09.2026 (Bauanleitung "Geschichtete Evidence-Architektur" Punkt 2, Fund waehrend
// Recherche zu no_network_outside_scope): fehlte hier bisher komplett -- Attestationen fuer den
// echten Kunden-CLI-Agent-Pfad (runCliAgentAndCommit()) galten dadurch faelschlich immer als
// ungueltig (network_policy war weder im Typ oben noch in einer eigenen Policy-Konstante bekannt).
const SANDBOX_ATTESTATION_POLICY_NETWORK_ENFORCED = {
  ...SANDBOX_ATTESTATION_POLICY_NO_NETWORK,
  network: "netns_egress_allowlisted_v1" as const,
};

const PROVENANCE_CAPABILITY = "memory.provenance.attached@1.0";
const DELETE_ENFORCED_CAPABILITY = "memory.delete.enforced@1.0";
const TENANT_ISOLATION_CAPABILITY = "memory.tenant.isolation@1.0";
const WRITE_INTEGRITY_CAPABILITY = "memory.write.integrity@1.0";
const TAMPER_EVIDENT_CAPABILITY = "memory.audit.tamper_evident@1.0";
const RECOVERY_VERIFIED_CAPABILITY = "memory.recovery.verified@1.0";
const DEVTASK_EXECUTION_CAPABILITY = "devtask.execution@1.0";
const MEMORY_WRITE_EVENT_PREFIX = "memory_write:";
const MEMORY_STATE_READ_EVENT_PREFIX = "memory_state_read:";
const TENANT_ACCESS_PROBE_EVENT_PREFIX = "tenant_access_probe:";
const MEMORY_CONTENT_CHANGE_EVENT_PREFIX = "memory_content_change:";
const AUDIT_CHAIN_CHECK_EVENT_PREFIX = "audit_chain_check:";
const MEMORY_RECOVERY_EVENT_PREFIX = "memory_recovery:";
const DEVTASK_CONTRACT_BOUND_PREFIX = "devtask_contract_bound:";
const DEVTASK_ATTEMPT_STARTED_PREFIX = "devtask_attempt_started:";
const DEVTASK_EXECUTION_CONTEXT_PREFIX = "devtask_execution_context:";
const DEVTASK_VALIDATION_PREFIX = "devtask_validation:";
const DEVTASK_HUMAN_APPROVAL_PREFIX = "devtask_human_approval:";
const DEVTASK_OUTCOME_PREFIX = "devtask_outcome:";

interface ProvenanceTraceEvent {
  entry_id: string;
  actual_agent_id: string;
  provenance_agent_id: string;
  actual_source_hash: string;
  provenance_source_hash: string;
}

interface MemoryStateReadTraceEvent {
  entry_id: string;
  exists: boolean;
  phase: "after_delete" | "after_replay_check";
  source: "storage_probe";
}

interface TenantAccessProbeTraceEvent {
  entry_id: string;
  requesting_tenant: string;
  target_tenant: string;
  allowed: boolean;
  source: "isolation_probe";
}

interface MemoryContentChangeTraceEvent {
  entry_id: string;
  phase: "before" | "after";
  content_hash: string;
  source: "content_probe";
}

interface AuditChainCheckTraceEvent {
  chain_valid: boolean;
  mutated_order: boolean;
  broken_link_at?: number;
  source: "audit_chain_probe";
}

interface MemoryRecoveryTraceEvent {
  snapshot_id: string;
  requested_state_hash: string;
  recovered_state_hash: string;
  restored: boolean;
  source: "recovery_probe";
}

interface DevTaskContractBoundTraceEvent {
  task_id: string;
  attempt_number: number;
  contract_hash: string;
  contract_schema_version: string;
  risk_class: string | null;
  protect_existing_tests?: boolean;
  test_protection_disclosure?: "disclosed" | "withheld_for_adversarial_evaluation";
}

interface DevTaskAttemptStartedTraceEvent {
  task_id: string;
  attempt_number: number;
  started_at: string;
}

interface DevTaskExecutionContextTraceEvent {
  task_id: string;
  attempt_number: number;
  sandbox_reference: string | null;
  execution_reference: string;
  executor: "deepseek" | "hermes" | "opencode" | "aider" | "cline";
  harness_id: string;
  adapter_version: string;
  adapter_version_sha256: string;
}

interface DevTaskValidationTraceEvent {
  task_id: string;
  attempt_number: number;
  validation_status: string;
  validation_reference: string;
}

interface DevTaskHumanApprovalTraceEvent {
  task_id: string;
  attempt_number: number;
  actor_id: string;
  approved_at: string | null;
  approval_reference: string;
}

interface DevTaskOutcomeTraceEvent {
  task_id: string;
  attempt_number: number;
  outcome: "COMPLETED" | "FAILED" | "ABORTED";
  completed_at: string | null;
  reference: string;
}

// Optional (25.08.2026, extended same day): always hashes the diff_stat summary line;
// diff_full_sha256 (when present) hashes the FULL `git diff --cached HEAD` content, captured in
// repoContributionPipeline.server.ts right before the commit -- the only point in the process
// where the full diff is still available. Purely informational here -- does not affect
// deriveOutcomeFromTrace, so bundles issued before this field existed keep verifying unchanged.
interface DevTaskDiffEvidenceTraceEvent {
  task_id: string;
  attempt_number: number;
  diff_stat_sha256: string;
  diff_full_sha256: string | null;
  scope: "diff_stat_only" | "diff_stat_and_full";
}

const DEVTASK_DIFF_EVIDENCE_PREFIX = "devtask_diff_evidence:";
const DEVTASK_CI_RESULT_PREFIX = "devtask_ci_result:";

// 05.09.2026 (Bauanleitung "Geschichtete Evidence-Architektur", Punkt 1): identische Kopie von
// evidenceBundle.server.ts. Bewusst nur "check_passes" -- der einzige Assertion-Typ, den die
// GitHub-API generisch (unabhaengig vom CI-System des Zielrepos) hergibt.
type AcceptanceAssertion = { type: "check_passes"; checkName: string };
interface AcceptanceCriterion { description: string; assertion?: AcceptanceAssertion }
// AcceptanceAssertionResult ist bereits oben (bei CustomerEvidenceV1) deklariert.

export function evaluateAcceptanceAssertions(
  criteria: AcceptanceCriterion[],
  checks: { name: string; conclusion: string }[],
): AcceptanceAssertionResult[] {
  return criteria.map((c) => {
    if (!c.assertion) return { description: c.description, satisfied: null };
    if (c.assertion.type === "check_passes") {
      const match = checks.find((chk) => chk.name === c.assertion!.checkName);
      return { description: c.description, satisfied: match ? match.conclusion === "success" : false };
    }
    return { description: c.description, satisfied: null };
  });
}

// 05.09.2026 (Bauanleitung "Geschichtete Evidence-Architektur", Punkt 0/1): identische Kopie von
// evidenceBundle.server.ts (kein Shared Import, siehe Datei-Header oben zu deriveApprovalClaimLadder).
const DEVTASK_SCOPE_VIOLATION_PREFIX = "devtask_scope_violation:";
interface DevTaskScopeViolationTraceEvent {
  task_id: string;
  attempt_number: number;
  violation_type: "scope_violation" | "tool_not_allowed" | "path_outside_allowlist";
  detail: string;
  tool?: string;
  path?: string;
  detected_at: string;
}

// 05.09.2026 (Bauanleitung "Geschichtete Evidence-Architektur", Punkt 2): identische Kopie von
// evidenceBundle.server.ts -- war bei Punkt 0 nur als Kommentar vorgemerkt, jetzt tatsaechlich
// dupliziert, weil Punkt 2 hier eine eigene, unabhaengige Auswertung braucht (deriveOutcomeFromTrace
// unten). "policy_derived" bleibt informativ, nur "observed"/"attested" duerfen blockieren.
const DEVTASK_NEGATIVE_CLAIM_PREFIX = "devtask_negative_claim:";
interface EvidenceRef {
  artifact: "runtime_trace" | "attestation" | "ci_check" | "signature";
  id: string;
  digest: string;
}

interface DevTaskNegativeClaimTraceEvent {
  task_id: string;
  attempt_number: number;
  claim: "no_network_outside_scope" | "no_secret_access" | "no_write_outside_allowlist" | (string & {});
  verified_by: string;
  strength: TrustLevel;
  result: boolean;
  evidence_ref?: EvidenceRef;
}

// spec/INVARIANTS.md: mehrere schwache Artefakte ergeben nie eine staerkere Stufe.
export const TRUST_LEVELS = [
  "policy_derived", "observed", "attested", "independently_witnessed", "cryptographically_verified",
] as const;
export type TrustLevel = typeof TRUST_LEVELS[number];
export interface TrustArtifactAssessment {
  artifact_id: string;
  trust_level: TrustLevel | "unknown";
  provenance_resolved: boolean;
  semantic_trust_level?: Exclude<TrustLevel, "cryptographically_verified">;
}
export interface TrustRequirementResult {
  satisfied: boolean;
  effective_level: TrustLevel | "unsupported";
  supporting_artifact_id?: string;
  reason?: "missing_provenance" | "insufficient_trust_level";
}
export function evaluateTrustRequirement(required: TrustLevel, artifacts: readonly TrustArtifactAssessment[]): TrustRequirementResult {
  const resolved = artifacts.filter((artifact) => artifact.provenance_resolved && artifact.trust_level !== "unknown");
  const semanticLevels = TRUST_LEVELS.slice(0, 4);
  const requiredRank = semanticLevels.indexOf(required as typeof semanticLevels[number]);
  const supporting = resolved.find((artifact) => {
    if (required === "cryptographically_verified") return artifact.trust_level === required;
    const semantic = artifact.trust_level === "cryptographically_verified"
      ? artifact.semantic_trust_level
      : artifact.trust_level;
    return semantic !== undefined && semanticLevels.indexOf(semantic as typeof semanticLevels[number]) >= requiredRank;
  });
  if (supporting) return { satisfied: true, effective_level: supporting.trust_level as TrustLevel, supporting_artifact_id: supporting.artifact_id };
  return { satisfied: false, effective_level: "unsupported", reason: resolved.length === 0 ? "missing_provenance" : "insufficient_trust_level" };
}

// 05.09.2026 (Bauanleitung "Geschichtete Evidence-Architektur", Punkt 3): identische Kopie von
// evidenceBundle.server.ts, gleiches Nachholmuster wie bei negative_claim in Punkt 2 -- war bei
// Punkt 0 nur als Kommentar vorgemerkt. Ein ungeloester Widerspruch (resolved:false) blockiert
// "verified" (deriveOutcomeFromTrace unten), unabhaengig davon ob CI/Tests sonst gruen sind.
const DEVTASK_CONTRADICTION_PREFIX = "devtask_contradiction:";
interface DevTaskContradictionRefTraceEvent {
  subject: string;
  property: string;
  previous_bundle_id: string;
  current_bundle_id: string;
  detected_at: string;
  resolved: boolean;
}

function parseDevTaskEvent<T>(event: string, prefix: string): T | null {
  if (!event.startsWith(prefix)) return null;
  try {
    return JSON.parse(event.slice(prefix.length)) as T;
  } catch {
    return null;
  }
}

export interface ClaimEvidenceRefAssessment {
  claim: string;
  supported: boolean;
  required: boolean;
  reason?: "missing_evidence_ref" | "unresolved_evidence_ref" | "digest_mismatch";
}

function expectedEvidenceArtifactDigest(bundle: EvidenceBundle, ref: EvidenceRef): string | null {
  let artifact: unknown;
  if (ref.artifact === "attestation" && ref.id === "controller_evidence.sandbox_attestation") {
    artifact = bundle.controller_evidence?.sandbox_attestation;
  } else if (ref.artifact === "runtime_trace" && ref.id === "trace_events:without_negative_claims") {
    artifact = bundle.trace_events.filter(event => !event.startsWith(DEVTASK_NEGATIVE_CLAIM_PREFIX));
  } else {
    return null;
  }
  if (artifact === null || artifact === undefined) return null;
  return "sha256:" + createHash("sha256").update(canonicalEvidenceJson(artifact)).digest("hex");
}

export function assessClaimEvidenceRefs(bundle: EvidenceBundle): ClaimEvidenceRefAssessment[] {
  return bundle.trace_events
    .map(event => parseDevTaskEvent<DevTaskNegativeClaimTraceEvent>(event, DEVTASK_NEGATIVE_CLAIM_PREFIX))
    .filter((claim): claim is DevTaskNegativeClaimTraceEvent => claim !== null)
    .map(claim => {
      const required = claim.strength === "observed" || claim.strength === "attested";
      if (!claim.evidence_ref) return { claim: claim.claim, supported: false, required: false, reason: "missing_evidence_ref" };
      const expected = expectedEvidenceArtifactDigest(bundle, claim.evidence_ref);
      if (expected === null) return { claim: claim.claim, supported: false, required, reason: "unresolved_evidence_ref" };
      if (expected !== claim.evidence_ref.digest) return { claim: claim.claim, supported: false, required, reason: "digest_mismatch" };
      return { claim: claim.claim, supported: true, required };
    });
}

function buildHashChain(events: string[]): string[] {
  const chain: string[] = [];
  let prev = "genesis";
  for (const event of events) {
    const hash = createHash("sha256").update(prev + event).digest("hex");
    chain.push(hash);
    prev = hash;
  }
  return chain;
}

function parseProvenanceEvent(event: string): ProvenanceTraceEvent | null {
  if (!event.startsWith(MEMORY_WRITE_EVENT_PREFIX)) {
    return null;
  }

  try {
    return JSON.parse(event.slice(MEMORY_WRITE_EVENT_PREFIX.length)) as ProvenanceTraceEvent;
  } catch {
    return null;
  }
}

// 05.09.2026 (Bauanleitung "Geschichtete Evidence-Architektur", Punkt 0): exportiert, damit ein
// Test direkt beweisen kann, dass diese unabhaengige Kopie und die Server-Originalfunktion
// (evaluateDevTaskExecutionTraceOutcome() in evidenceBundle.server.ts) bei einem
// devtask_scope_violation-Event dasselbe Ergebnis liefern -- kein neuer CLI-Oberflaechen-Umfang,
// nur Testbarkeit, gleiche Konvention wie der bestehende verifyBundleObject()-Export.
export function deriveOutcomeFromTrace(capability: string, events: string[]): "verified" | "failed" | "inconclusive" {
  if (capability === PROVENANCE_CAPABILITY) {
    const writes = events.map(parseProvenanceEvent).filter((event): event is ProvenanceTraceEvent => Boolean(event));
    if (writes.length === 0) {
      return "inconclusive";
    }

    const hasMismatch = writes.some((write) => {
      if (!write.actual_agent_id || !write.provenance_agent_id || !write.actual_source_hash || !write.provenance_source_hash) {
        return true;
      }

      return write.actual_agent_id !== write.provenance_agent_id || write.actual_source_hash !== write.provenance_source_hash;
    });

    return hasMismatch ? "failed" : "verified";
  }

  if (capability === DELETE_ENFORCED_CAPABILITY) {
    const reads = events
      .map((event) => {
        if (!event.startsWith(MEMORY_STATE_READ_EVENT_PREFIX)) return null;
        try {
          return JSON.parse(event.slice(MEMORY_STATE_READ_EVENT_PREFIX.length)) as MemoryStateReadTraceEvent;
        } catch {
          return null;
        }
      })
      .filter((event): event is MemoryStateReadTraceEvent => Boolean(event));

    const afterDeleteRead = reads.find((read) => read.phase === "after_delete" && read.source === "storage_probe");
    if (!afterDeleteRead) {
      return "inconclusive";
    }

    if (afterDeleteRead.exists) {
      return "failed";
    }

    const replayViolation = reads.some((read) => read.phase === "after_replay_check" && read.source === "storage_probe" && read.exists);
    return replayViolation ? "failed" : "verified";
  }

  if (capability === TENANT_ISOLATION_CAPABILITY) {
    const probes = events
      .map((event) => {
        if (!event.startsWith(TENANT_ACCESS_PROBE_EVENT_PREFIX)) return null;
        try {
          return JSON.parse(event.slice(TENANT_ACCESS_PROBE_EVENT_PREFIX.length)) as TenantAccessProbeTraceEvent;
        } catch {
          return null;
        }
      })
      .filter((event): event is TenantAccessProbeTraceEvent => Boolean(event));

    if (probes.length === 0) {
      return "inconclusive";
    }

    const crossTenantProbes = probes.filter((probe) => probe.requesting_tenant !== probe.target_tenant);
    if (crossTenantProbes.length === 0) {
      return "inconclusive";
    }

    const leak = crossTenantProbes.some((probe) => probe.allowed);
    return leak ? "failed" : "verified";
  }

  if (capability === WRITE_INTEGRITY_CAPABILITY) {
    const changes = events
      .map((event) => {
        if (!event.startsWith(MEMORY_CONTENT_CHANGE_EVENT_PREFIX)) return null;
        try {
          return JSON.parse(event.slice(MEMORY_CONTENT_CHANGE_EVENT_PREFIX.length)) as MemoryContentChangeTraceEvent;
        } catch {
          return null;
        }
      })
      .filter((event): event is MemoryContentChangeTraceEvent => Boolean(event));

    if (changes.length === 0) {
      return "inconclusive";
    }

    const before = changes.find((change) => change.phase === "before" && change.source === "content_probe");
    const after = changes.find((change) => change.phase === "after" && change.source === "content_probe");

    if (!before || !after) {
      return "inconclusive";
    }

    return before.content_hash === after.content_hash ? "failed" : "verified";
  }

  if (capability === TAMPER_EVIDENT_CAPABILITY) {
    const checks = events
      .map((event) => {
        if (!event.startsWith(AUDIT_CHAIN_CHECK_EVENT_PREFIX)) return null;
        try {
          return JSON.parse(event.slice(AUDIT_CHAIN_CHECK_EVENT_PREFIX.length)) as AuditChainCheckTraceEvent;
        } catch {
          return null;
        }
      })
      .filter((event): event is AuditChainCheckTraceEvent => Boolean(event));

    if (checks.length === 0) {
      return "inconclusive";
    }

    const chainBroken = checks.some((check) => check.source === "audit_chain_probe" && !check.chain_valid);
    return chainBroken ? "failed" : "verified";
  }

  if (capability === RECOVERY_VERIFIED_CAPABILITY) {
    const recoveries = events
      .map((event) => {
        if (!event.startsWith(MEMORY_RECOVERY_EVENT_PREFIX)) return null;
        try {
          return JSON.parse(event.slice(MEMORY_RECOVERY_EVENT_PREFIX.length)) as MemoryRecoveryTraceEvent;
        } catch {
          return null;
        }
      })
      .filter((event): event is MemoryRecoveryTraceEvent => Boolean(event));

    if (recoveries.length === 0) {
      return "inconclusive";
    }

    const badRestore = recoveries.some(
      (r) => r.source !== "recovery_probe" || !r.restored || r.requested_state_hash !== r.recovered_state_hash,
    );
    return badRestore ? "failed" : "verified";
  }

  if (capability === DEVTASK_EXECUTION_CAPABILITY) {
    const contractBound = events.map((e) => parseDevTaskEvent<DevTaskContractBoundTraceEvent>(e, DEVTASK_CONTRACT_BOUND_PREFIX)).find(Boolean) ?? null;
    const attemptStarted = events.map((e) => parseDevTaskEvent<DevTaskAttemptStartedTraceEvent>(e, DEVTASK_ATTEMPT_STARTED_PREFIX)).find(Boolean) ?? null;
    const validation = events.map((e) => parseDevTaskEvent<DevTaskValidationTraceEvent>(e, DEVTASK_VALIDATION_PREFIX)).find(Boolean) ?? null;
    const humanApproval = events.map((e) => parseDevTaskEvent<DevTaskHumanApprovalTraceEvent>(e, DEVTASK_HUMAN_APPROVAL_PREFIX)).find(Boolean) ?? null;
    const outcome = events.map((e) => parseDevTaskEvent<DevTaskOutcomeTraceEvent>(e, DEVTASK_OUTCOME_PREFIX)).find(Boolean) ?? null;

    if (!contractBound || !attemptStarted || !outcome) {
      return "inconclusive";
    }

    const present = [contractBound, attemptStarted, outcome, ...(validation ? [validation] : []), ...(humanApproval ? [humanApproval] : [])];
    const sameRun = present.every((e) => e.task_id === contractBound.task_id && e.attempt_number === contractBound.attempt_number);
    if (!sameRun) {
      return "failed";
    }

    if (outcome.outcome === "COMPLETED" && !humanApproval) {
      return "failed";
    }

    if (outcome.outcome === "COMPLETED" && validation && validation.validation_status !== "passed" && validation.validation_status !== "passed_override") {
      return "failed";
    }

    const scopeViolations = events
      .map((e) => parseDevTaskEvent<DevTaskScopeViolationTraceEvent>(e, DEVTASK_SCOPE_VIOLATION_PREFIX))
      .filter((v): v is DevTaskScopeViolationTraceEvent => v !== null && v.task_id === contractBound.task_id && v.attempt_number === contractBound.attempt_number);
    if (scopeViolations.length > 0) {
      return "failed";
    }

    // Bauanleitung "Geschichtete Evidence-Architektur", Punkt 2 (05.09.2026): identische Auswertung
    // wie evidenceBundle.server.ts (kein Shared Import) -- nur "observed"/"attested" mit result:false
    // blockiert, "policy_derived" bleibt informativ.
    const failedIndependentNegativeClaims = events
      .map((e) => parseDevTaskEvent<DevTaskNegativeClaimTraceEvent>(e, DEVTASK_NEGATIVE_CLAIM_PREFIX))
      .filter((v): v is DevTaskNegativeClaimTraceEvent => v !== null && v.task_id === contractBound.task_id && v.attempt_number === contractBound.attempt_number
        && v.strength !== "policy_derived" && v.result === false);
    if (failedIndependentNegativeClaims.length > 0) {
      return "failed";
    }

    // Bauanleitung "Geschichtete Evidence-Architektur", Punkt 3 (05.09.2026): identische Auswertung
    // wie evidenceBundle.server.ts -- ein UNGELOESTER Widerspruch blockiert "verified".
    const unresolvedContradictions = events
      .map((e) => parseDevTaskEvent<DevTaskContradictionRefTraceEvent>(e, DEVTASK_CONTRADICTION_PREFIX))
      .filter((v): v is DevTaskContradictionRefTraceEvent => v !== null && v.resolved === false);
    if (unresolvedContradictions.length > 0) {
      return "failed";
    }

    return "verified";
  }

  return "inconclusive";
}

function evidenceSignerKeyId(publicKey: string): string {
  return `ed25519:${createHash("sha256").update(publicKey).digest("hex")}`;
}

function riskRank(riskClass: string | null | undefined): number {
  const match = /^R([0-4])$/.exec(riskClass ?? "");
  return match ? Number(match[1]) : 4;
}

// 05.09.2026 (Bauanleitung 1.3): identische Kopie von deriveApprovalClaimLadder() in
// server/services/mrtb/evidenceBundle.server.ts (kein Shared Import, siehe Datei-Header oben).
function deriveApprovalClaimLadder(outcome: "verified" | "failed" | "inconclusive", approvalReference: string | null | undefined): ClaimLadder {
  if (outcome !== "verified") return "L0";
  if (!approvalReference) return "L2";
  return approvalReference.startsWith("webauthn_passkey:") ? "L2" : "L1";
}

function requiredDevTaskEvidenceV2(events: string[], controller?: DevTaskControllerEvidenceV2): string[] {
  const contract = events.map((e) => parseDevTaskEvent<DevTaskContractBoundTraceEvent>(e, DEVTASK_CONTRACT_BOUND_PREFIX)).find(Boolean) ?? null;
  const outcome = events.map((e) => parseDevTaskEvent<DevTaskOutcomeTraceEvent>(e, DEVTASK_OUTCOME_PREFIX)).find(Boolean) ?? null;
  const required = ["contract", "attempt", "execution_context", "validation", "outcome", "base_commit", "diff_full"];
  if (outcome?.outcome === "COMPLETED") required.push("human_approval", "result_reference", "ci_result");
  if (riskRank(contract?.risk_class) >= 3) required.push("sandbox_attestation");
  if (controller?.repository_state) required.push("repository_state");
  if (contract?.protect_existing_tests === true) required.push("test_integrity_policy");
  return required;
}

function deriveDevTaskV2Outcome(events: string[], controller: DevTaskControllerEvidenceV2): "verified" | "failed" | "inconclusive" {
  const contract = events.map((e) => parseDevTaskEvent<DevTaskContractBoundTraceEvent>(e, DEVTASK_CONTRACT_BOUND_PREFIX)).find(Boolean) ?? null;
  const expectedTestPolicy = buildTestIntegrityPolicyEvidence(contract?.protect_existing_tests === true, controller.repository_state);
  if (contract?.protect_existing_tests === true || controller.test_integrity_policy) {
    if (JSON.stringify(controller.test_integrity_policy) !== JSON.stringify(expectedTestPolicy)) return "failed";
    if (expectedTestPolicy.status === "failed") return "failed";
  }
  const base = deriveOutcomeFromTrace(DEVTASK_EXECUTION_CAPABILITY, events);
  if (base !== "verified") return base;
  const context = events.map((e) => parseDevTaskEvent<DevTaskExecutionContextTraceEvent>(e, DEVTASK_EXECUTION_CONTEXT_PREFIX)).find(Boolean) ?? null;
  const validation = events.map((e) => parseDevTaskEvent<DevTaskValidationTraceEvent>(e, DEVTASK_VALIDATION_PREFIX)).find(Boolean) ?? null;
  const approval = events.map((e) => parseDevTaskEvent<DevTaskHumanApprovalTraceEvent>(e, DEVTASK_HUMAN_APPROVAL_PREFIX)).find(Boolean) ?? null;
  const diff = events.map((e) => parseDevTaskEvent<DevTaskDiffEvidenceTraceEvent>(e, DEVTASK_DIFF_EVIDENCE_PREFIX)).find(Boolean) ?? null;
  const outcome = events.map((e) => parseDevTaskEvent<DevTaskOutcomeTraceEvent>(e, DEVTASK_OUTCOME_PREFIX)).find(Boolean) ?? null;
  const ciResult = events.map((e) => parseDevTaskEvent<any>(e, DEVTASK_CI_RESULT_PREFIX)).find(Boolean) ?? null;
  if (controller.task_id !== contract?.task_id || controller.attempt_number !== contract?.attempt_number) return "failed";
  if (controller.execution_reference !== context?.execution_reference) return "failed";
  const hasExecutorProvenance = Boolean(context && (context.executor || context.harness_id || context.adapter_version || context.adapter_version_sha256));
  if (hasExecutorProvenance && (!context || !["deepseek", "hermes", "opencode", "aider", "cline"].includes(context.executor) ||
      !/^[a-z0-9][a-z0-9._-]*$/.test(context.harness_id) ||
      !/^[a-z0-9][a-z0-9._@/-]*$/.test(context.adapter_version) ||
      context.adapter_version_sha256 !== sha256(context.adapter_version))) return "failed";
  if (controller.validation_reference !== validation?.validation_reference) return "failed";
  if (controller.diff_stat_sha256 !== diff?.diff_stat_sha256) return "failed";
  if (controller.diff_full_sha256 !== diff?.diff_full_sha256) return "failed";
  if (controller.diff_full !== null && controller.diff_full_sha256 !== null &&
      createHash("sha256").update(controller.diff_full).digest("hex") !== controller.diff_full_sha256) return "failed";
  if (outcome?.outcome === "COMPLETED" && controller.approval_reference !== approval?.approval_reference) return "failed";
  if (outcome?.outcome === "COMPLETED" && ciResult) {
    if (ciResult.task_id !== controller.task_id || ciResult.attempt_number !== controller.attempt_number ||
      ciResult.result_commit !== controller.repository_state?.result_commit ||
      ciResult.source !== "github_checks_and_statuses" || !Number.isFinite(Date.parse(ciResult.checked_at))) return "failed";
    if (ciResult.conclusion === "failure") return "failed";
    if (ciResult.conclusion !== "success") return "inconclusive";
  }
  const repository = controller.repository_state;
  if (repository) {
    const hashOk = (value: string | null) => value === null || /^[a-f0-9]{64}$/.test(value);
    if (repository.schema_version !== "repository-state@1.0" || repository.base_commit !== controller.base_commit ||
      !repository.result_commit || !hashOk(repository.tree_before_sha256) || !hashOk(repository.tree_after_sha256) ||
      repository.tree_before_sha256 === repository.tree_after_sha256 || repository.changed_files.length === 0 ||
      repository.changed_files.some((file) => !file.path || !["A", "M", "D"].includes(file.status) ||
        !hashOk(file.before_sha256) || !hashOk(file.after_sha256) ||
        (file.status === "A" && file.before_sha256 !== null) || (file.status === "D" && file.after_sha256 !== null) ||
        (file.status !== "A" && file.before_sha256 === null) || (file.status !== "D" && file.after_sha256 === null))) return "failed";
  }
  const attestation = controller.sandbox_attestation;
  const attestationHash = attestation ? `sandbox-attestation:sha256:${createHash("sha256").update(JSON.stringify(attestation)).digest("hex")}` : null;
  if (controller.sandbox_reference !== context?.sandbox_reference || controller.sandbox_reference !== attestationHash) return "failed";
  // 29.08.2026 ("Code-Pruefstand"): welche Policy-Konstante fuer die policy_sha256-Nachrechnung gilt,
  // haengt vom behaupteten Profil ab; network_capture muss dazu konsistent sein (befuellt genau
  // dann wenn netns_egress_logged_v1/netns_egress_allowlisted_v1 behauptet wird, sonst null) --
  // identische Pruefung wie in server/services/mrtb/evidenceBundle.server.ts (kein Shared Import,
  // siehe Datei-Header oben). 05.09.2026: drittes Profil ergaenzt (siehe Fund-Kommentar bei
  // SANDBOX_ATTESTATION_POLICY_NETWORK_ENFORCED oben).
  const expectedPolicy = attestation?.network_policy === "netns_egress_logged_v1"
    ? SANDBOX_ATTESTATION_POLICY_NETWORK_CAPTURE
    : attestation?.network_policy === "netns_egress_allowlisted_v1"
    ? SANDBOX_ATTESTATION_POLICY_NETWORK_ENFORCED
    : SANDBOX_ATTESTATION_POLICY_NO_NETWORK;
  const networkCaptureConsistent = attestation
    ? (attestation.network_policy === "netns_egress_logged_v1" || attestation.network_policy === "netns_egress_allowlisted_v1"
      ? Boolean(attestation.network_capture &&
          attestation.network_capture.schema_version === "egress-capture@1.0" &&
          /^[a-f0-9]{64}$/.test(attestation.network_capture.dns_queries_sha256) &&
          /^[a-f0-9]{64}$/.test(attestation.network_capture.connections_sha256))
      : attestation.network_capture === null)
    : false;
  const sandboxValid = Boolean(attestation && attestation.schema_version === "sandbox-attestation@2.0" &&
    attestation.os_isolation_available && attestation.git_metadata_absent && attestation.controller_checkout_separated &&
    (attestation.network_policy === "bubblewrap_unshare_net_fail_closed" || attestation.network_policy === "netns_egress_logged_v1" || attestation.network_policy === "netns_egress_allowlisted_v1") &&
    networkCaptureConsistent &&
    attestation.environment_policy === "bubblewrap_clearenv" &&
    attestation.process_policy === "systemd_scope_limits_and_kill" &&
    attestation.agent_id === controller.agent_run_id &&
    attestation.policy_sha256 === createHash("sha256").update(JSON.stringify(expectedPolicy, Object.keys(expectedPolicy).sort())).digest("hex") &&
    [attestation.snapshot_sha256, attestation.policy_sha256, attestation.handoff_manifest_sha256, attestation.rejected_manifest_sha256]
      .every((hash) => /^[a-f0-9]{64}$/.test(hash)));
  const present: Record<string, boolean> = {
    contract: Boolean(contract), attempt: events.some((e) => e.startsWith(DEVTASK_ATTEMPT_STARTED_PREFIX)),
    execution_context: Boolean(context && controller.execution_reference), validation: Boolean(validation && controller.validation_reference),
    outcome: Boolean(outcome), base_commit: Boolean(controller.base_commit), result_reference: Boolean(controller.result_reference),
    diff_full: Boolean(controller.diff_full && diff?.diff_full_sha256 && controller.diff_full_sha256),
    human_approval: Boolean(approval && controller.approval_reference),
    ci_result: Boolean(ciResult),
    repository_state: Boolean(repository),
    test_integrity_policy: controller.test_integrity_policy?.status === "passed",
    sandbox_attestation: sandboxValid,
  };
  return requiredDevTaskEvidenceV2(events, controller).every((name) => present[name]) ? "verified" : "inconclusive";
}

// 06.09.2026: deriveApprovalClaimLadder() wurde am 05.09. (Passkey-Haertung) von "jedes verified
// Bundle = L2" auf eine echte L1(Token)/L2(Passkey)-Unterscheidung praezisiert -- Bundles, die
// VOR dieser Aenderung mit dem alten, groberen Massstab signiert wurden, tragen dadurch dauerhaft
// einen zu hohen eingefrorenen Wert (z.B. signiert L2, heute nur noch L1 herleitbar). Live gefunden
// beim Bau der Verifier-Walkthrough-Seite: genau das liess die beiden oeffentlichen Demo-Bundles
// PR #33/#36 mit v2_derived_result_mismatch scheitern, obwohl unveraendert. Gleiches Prinzip wie
// Punkt 0 dieser Bauanleitung (fehlendes Feld -> niedrigeres Level, nicht Ablehnung): eine
// Herabstufung gegenueber dem signierten Wert ist kein Faelschungsversuch, eine Hochstufung schon.
const CLAIM_LADDER_RANK: Record<EvidenceBundle["claim_ladder"], number> = { L0: 0, L1: 1, L2: 2, L3: 3, L4: 4 };
function claimLadderRank(ladder: EvidenceBundle["claim_ladder"]): number { return CLAIM_LADDER_RANK[ladder]; }

export function verifyBundleObject(bundle: EvidenceBundle, trustedPublicKey?: string, trustedApprovalPublicKey?: string): { ok: boolean; reason?: string; verified_claim_ladder?: EvidenceBundle["claim_ladder"] } {
  // rfc3161_timestamp/observer_receipt werden IMMER erst nach dem Signieren angehaengt -- waren
  // nie Teil der signierten Nutzlast, muessen hier ebenso ausgeschlossen werden (siehe
  // verifyRfc3161Binding()/crossCheckObserverReceipt() fuer die getrennten Zusatzpruefungen).
  const { signature, public_key, rfc3161_timestamp, approval_attestation, observer_receipt, ...payload } = bundle;

  // Fail-closed: siehe Kommentar bei DEVTASK_V2_SCHEMA_VERSIONS oben.
  if (bundle.schema_version?.startsWith("evidence-package@") && !isDevTaskV2Schema(bundle.schema_version)) {
    return { ok: false, reason: "unsupported_schema_version" };
  }
  if (bundle.schema_version === "evidence-package@2.2") {
    const specError = validateDevTaskEvidenceSpecV1(bundle);
    if (specError) return { ok: false, reason: specError };
  }
  if (isDevTaskV2Schema(bundle.schema_version)) {
    if (!trustedPublicKey) return { ok: false, reason: "missing_trust_anchor" };
    if (public_key !== trustedPublicKey || bundle.signer_key_id !== evidenceSignerKeyId(trustedPublicKey)) {
      return { ok: false, reason: "untrusted_signer" };
    }
    if (!bundle.controller_evidence) return { ok: false, reason: "missing_controller_evidence" };
  }

  const signedPayload = bundle.schema_version === "evidence-package@2.2" ? canonicalEvidenceJson(payload) : JSON.stringify(payload);
  const isValidSignature = verify(
    null,
    Buffer.from(signedPayload),
    public_key,
    Buffer.from(signature, "base64"),
  );

  if (!isValidSignature) {
    return { ok: false, reason: "invalid_signature" };
  }
  if (bundle.approval_attestation_required) {
    if (!approval_attestation) return { ok: false, reason: "missing_approval_attestation" };
    if (!trustedApprovalPublicKey) return { ok: false, reason: "missing_approval_trust_anchor" };
    const { signature: approvalSignature, public_key: approvalPublicKey, signer_key_id, ...approvalPayload } = approval_attestation;
    // 06.09.2026 (identischer Fix wie evidenceBundle.server.ts, live gefunden beim Bau der
    // Proof-Policy-Gate-Tests, Punkt 3): observer_receipt wird in der Produktions-Pipeline IMMER
    // erst NACH attachApprovalAttestation() angehaengt -- bundle_sha256 wurde ohne dieses Feld
    // berechnet. Ohne den Ausschluss haette jedes COMPLETED, freigegebene UND vom Observer
    // bezeugte Bundle hier faelschlich "approval_bundle_hash_mismatch" geliefert.
    const { approval_attestation: _ignored, observer_receipt: _observerReceiptIgnored, ...bundleWithoutApproval } = bundle;
    if (approvalPublicKey !== trustedApprovalPublicKey || signer_key_id !== evidenceSignerKeyId(trustedApprovalPublicKey)) return { ok: false, reason: "untrusted_approval_signer" };
    if (approvalPayload.bundle_sha256 !== sha256(JSON.stringify(bundleWithoutApproval))) return { ok: false, reason: "approval_bundle_hash_mismatch" };
    if (!verify(null, Buffer.from(JSON.stringify(approvalPayload)), approvalPublicKey, Buffer.from(approvalSignature, "base64"))) return { ok: false, reason: "invalid_approval_signature" };
  }

  const rebuilt = buildHashChain(bundle.trace_events);
  const chainOk = rebuilt.length === bundle.trace_hash_chain.length && rebuilt.every((h, i) => h === bundle.trace_hash_chain[i]);
  if (!chainOk) {
    return { ok: false, reason: "hash_chain_mismatch" };
  }

  let verifiedClaimLadder: EvidenceBundle["claim_ladder"] | undefined;
  if (isDevTaskV2Schema(bundle.schema_version) && bundle.controller_evidence) {
    const unsupportedRequiredClaim = assessClaimEvidenceRefs(bundle).find(claim => !claim.supported && claim.required);
    if (unsupportedRequiredClaim) return { ok: false, reason: "unsupported_required_claim:" + unsupportedRequiredClaim.claim };
    const snapshot = bundle.controller_evidence.contract_snapshot;
    if (snapshot != null) {
      const contracts = bundle.trace_events.map(e => parseDevTaskEvent<DevTaskContractBoundTraceEvent>(e, DEVTASK_CONTRACT_BOUND_PREFIX)).filter(e => e !== null);
      const contract = contracts.find(e => e.task_id === bundle.controller_evidence!.task_id && e.attempt_number === bundle.controller_evidence!.attempt_number);
      if (!contract || createHash("sha256").update(JSON.stringify(snapshot)).digest("hex") !== contract.contract_hash) {
        return { ok: false, reason: "contract_snapshot_hash_mismatch" };
      }
    }
    const required = requiredDevTaskEvidenceV2(bundle.trace_events, bundle.controller_evidence);
    if (JSON.stringify(bundle.required_evidence ?? []) !== JSON.stringify(required)) {
      return { ok: false, reason: "required_evidence_mismatch" };
    }
    const derived = deriveDevTaskV2Outcome(bundle.trace_events, bundle.controller_evidence);
    const ladder = deriveApprovalClaimLadder(derived, bundle.controller_evidence.approval_reference);
    if (bundle.outcome !== derived) {
      return { ok: false, reason: "v2_derived_result_mismatch" };
    }
    if (claimLadderRank(ladder) > claimLadderRank(bundle.claim_ladder)) {
      return { ok: false, reason: "v2_derived_result_mismatch" };
    }
    verifiedClaimLadder = claimLadderRank(ladder) < claimLadderRank(bundle.claim_ladder) ? ladder : bundle.claim_ladder;
  }

  if (bundle.schema_version === "evidence-package@2.1" ||
      (bundle.schema_version === "evidence-package@2.2" && bundle.customer_evidence !== undefined)) {
    if (!bundle.customer_evidence) return { ok: false, reason: "missing_customer_evidence" };
    const expectedSummary = buildCustomerSummaryDe(bundle.customer_evidence);
    if (bundle.customer_evidence.customer_summary !== expectedSummary) {
      return { ok: false, reason: "customer_summary_mismatch" };
    }
    if (bundle.controller_evidence && bundle.customer_evidence.approval.approval_reference !== bundle.controller_evidence.approval_reference) {
      return { ok: false, reason: "customer_approval_reference_mismatch" };
    }
  }

  if (!isDevTaskV2Schema(bundle.schema_version) && (
    bundle.capability === PROVENANCE_CAPABILITY ||
    bundle.capability === DELETE_ENFORCED_CAPABILITY ||
    bundle.capability === TENANT_ISOLATION_CAPABILITY ||
    bundle.capability === WRITE_INTEGRITY_CAPABILITY ||
    bundle.capability === TAMPER_EVIDENT_CAPABILITY ||
    bundle.capability === RECOVERY_VERIFIED_CAPABILITY ||
    bundle.capability === DEVTASK_EXECUTION_CAPABILITY
  )) {
    const derivedOutcome = deriveOutcomeFromTrace(bundle.capability, bundle.trace_events);
    if (bundle.outcome !== derivedOutcome) {
      return {
        ok: false,
        reason: `trace_outcome_mismatch:declared=${bundle.outcome}:derived=${derivedOutcome}`,
      };
    }
  }

  if (bundle.outcome !== "verified") {
    return { ok: false, reason: `non_verified_outcome:${bundle.outcome}` };
  }

  return verifiedClaimLadder !== undefined ? { ok: true, verified_claim_ladder: verifiedClaimLadder } : { ok: true };
}

// Normative Feldliste: spec/devtask.execution@1.0.schema.json.
export function validateDevTaskEvidenceSpecV1(bundle: EvidenceBundle): string | null {
  const required = [
    "schema_version", "spec_version", "bundle_id", "capability", "run_id", "claim_ladder",
    "executed_at", "trace_events", "trace_hash_chain", "outcome", "signature", "public_key",
    "signer_key_id", "controller_evidence", "required_evidence", "approval_attestation_required",
  ] as const;
  for (const field of required) if (!Object.hasOwn(bundle, field) || bundle[field] === undefined) {
    return `spec_validation_failed:missing_required_field:${field}`;
  }
  if (bundle.spec_version !== DEVTASK_EVIDENCE_SPEC_VERSION) return "spec_validation_failed:unsupported_spec_version";
  if (bundle.capability !== DEVTASK_EXECUTION_CAPABILITY) return "spec_validation_failed:capability_mismatch";
  if (!["L0", "L1", "L2"].includes(bundle.claim_ladder)) return "spec_validation_failed:claim_ladder_out_of_range";
  if (!Array.isArray(bundle.trace_events) || !bundle.trace_events.every(value => typeof value === "string")) return "spec_validation_failed:trace_events";
  if (!Array.isArray(bundle.trace_hash_chain) || !bundle.trace_hash_chain.every(value => /^[a-f0-9]{64}$/.test(value))) return "spec_validation_failed:trace_hash_chain";
  const controller = bundle.controller_evidence;
  const controllerRequired = [
    "producer", "task_id", "attempt_number", "base_commit", "result_reference", "diff_stat_sha256",
    "diff_full", "diff_full_sha256", "execution_reference", "validation_reference",
    "approval_reference", "sandbox_reference", "sandbox_attestation", "agent_run_id",
  ] as const;
  if (!controller) return "spec_validation_failed:missing_required_field:controller_evidence";
  for (const field of controllerRequired) if (!Object.hasOwn(controller, field)) {
    return `spec_validation_failed:missing_controller_field:${field}`;
  }
  if (controller.producer !== "privileged_controller" || typeof controller.task_id !== "string" ||
      !controller.task_id || !Number.isInteger(controller.attempt_number) || controller.attempt_number < 1) {
    return "spec_validation_failed:controller_evidence";
  }
  return null;
}

// 04.09.2026 (Bauanleitung 1.2): zweiter, unabhaengiger Veroeffentlichungskanal fuer den
// Trust-Anchor neben bewusstki.de -- derselbe JSON-Inhalt, manuell nach jeder Rotation in DIESES
// Repo gespiegelt (siehe scripts/publish-trust-anchor.mjs im Hauptrepo). Beide Hosts (Hetzner/Caddy
// vs. GitHub) sind unabhaengige Infrastruktur; ein Kompromiss des einen kompromittiert den anderen
// nicht automatisch.
const DEFAULT_TRUST_ANCHOR_CHANNELS = [
  "https://bewusstki.de/.well-known/alex-pubkey.json",
  "https://raw.githubusercontent.com/Alex-Proof/alex-mrtb-verify-bundle/main/trust-anchor.json",
];

export interface TrustAnchorChannelResult { url: string; key_id: string | null; public_key_pem: string | null; error?: string }
export interface TrustAnchorConsensus {
  purpose: "evidence_package" | "human_approval";
  channels: TrustAnchorChannelResult[];
  agreed_key_id: string | null;
  agreed_public_key_pem: string | null;
  agreement_count: number;
  total_channels: number;
  divergent: boolean;
}

/** Fragt alle bekannten Kanaele unabhaengig ab und meldet explizit, wie viele denselben Key-Id
 * bestaetigen -- statt still auf einen einzelnen Kanal (bewusstki.de) zu vertrauen. Ein
 * abweichender oder nicht erreichbarer Kanal blockiert die Pruefung NICHT (die Signaturpruefung
 * selbst bleibt die harte Schranke), wird aber unuebersehbar als `divergent`/Fehler gemeldet.
 * WICHTIG: liefert den PEM-Inhalt DIREKT aus den Kanaelen, niemals aus dem zu pruefenden Bundle
 * selbst -- sonst waere der Konsens-Vergleich zirkulaer (ein gefaelschtes Bundle koennte sich
 * sonst einfach selbst als vertrauenswuerdig bestaetigen). */
export async function crossCheckTrustAnchor(
  purpose: "evidence_package" | "human_approval",
  channels: string[] = DEFAULT_TRUST_ANCHOR_CHANNELS,
): Promise<TrustAnchorConsensus> {
  const results: TrustAnchorChannelResult[] = [];
  for (const url of channels) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as any;
      const keyId: string | null = purpose === "evidence_package" ? (data.key_id ?? null) : (data.approval_signer?.key_id ?? null);
      const pem: string | null = purpose === "evidence_package" ? (data.public_key_pem ?? null) : (data.approval_signer?.public_key_pem ?? null);
      results.push({ url, key_id: keyId, public_key_pem: pem });
    } catch (error) {
      results.push({ url, key_id: null, public_key_pem: null, error: error instanceof Error ? error.message : String(error) });
    }
  }
  const countsByKeyId = new Map<string, number>();
  for (const r of results) if (r.key_id) countsByKeyId.set(r.key_id, (countsByKeyId.get(r.key_id) ?? 0) + 1);
  let agreedKeyId: string | null = null;
  let agreementCount = 0;
  for (const [keyId, count] of countsByKeyId) if (count > agreementCount) { agreedKeyId = keyId; agreementCount = count; }
  const distinctKeyIds = new Set(results.filter((r) => r.key_id).map((r) => r.key_id));
  const agreedPem = agreedKeyId ? (results.find((r) => r.key_id === agreedKeyId)?.public_key_pem ?? null) : null;
  return {
    purpose, channels: results, agreed_key_id: agreedKeyId, agreed_public_key_pem: agreedPem,
    agreement_count: agreementCount, total_channels: channels.length, divergent: distinctKeyIds.size > 1,
  };
}

function printConsensus(label: string, consensus: TrustAnchorConsensus): void {
  console.log(`   Trust-Anchor (${label}): ${consensus.agreement_count}/${consensus.total_channels} Kanaele bestaetigen ${consensus.agreed_key_id ?? "keinen gemeinsamen Key"}`);
  for (const c of consensus.channels) {
    console.log(`     - ${c.url}: ${c.error ? `Fehler (${c.error})` : c.key_id}`);
  }
  if (consensus.divergent) {
    console.warn(`   ⚠ Kanaele weichen voneinander ab -- moeglicher Trust-Anchor-Kompromiss oder veraltete Kopie. Nicht stillschweigend ignorieren.`);
  }
}

// 05.09.2026 (Bauanleitung 1.4, Rest): der Kern -- ci_result als Pflicht-Gate -- war bereits
// fertig (siehe deriveDevTaskV2Outcome() oben, present.ci_result). Was fehlte: der signierte
// Diff wird nur INTERN gegen sich selbst geprueft (diff_full_sha256 stimmt mit dem mitgelieferten
// diff_full ueberein) -- das beweist Konsistenz des Bundles, nicht dass der Diff wirklich dem
// entspricht, was tatsaechlich auf GitHub gelandet ist. Ein kompromittierter/fehlerhafter
// Controller koennte intern konsistent luegen. Portiert die L2-Pruefung aus den manuellen
// prove-pr-*.sh-Skripten (alex-mrtb-verify-bundle-Repo) hierher, als automatischen Schritt statt
// eines Handablaufs pro PR: echter `git fetch` + `git diff` gegen den echten GitHub-Remote,
// Ergebnis-Hash gegen controller_evidence.diff_full_sha256 verglichen. Laeuft NUR hier im
// eigenstaendigen CLI-Verifier (braucht Netzwerk + git-Binary + ambiente Git-Credentials des
// Aufrufers fuer private Repos) -- nicht in der synchronen, reinen verifyBundleObject()/
// verifyEvidenceBundle(), die auch server-seitig in schnellen, netzwerkfreien Pfaden laeuft.
export interface GitHubDiffCheckResult {
  ok: boolean;
  reason?: string;
  repo?: string;
  base_commit?: string;
  result_commit?: string;
}

const GITHUB_OWNER_REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
const GIT_COMMIT_SHA_RE = /^[0-9a-fA-F]{7,40}$/;

function parseGithubPrReference(resultReference: string | null | undefined): { owner: string; repo: string } | null {
  if (!resultReference || !resultReference.startsWith("github_pr:")) return null;
  const url = resultReference.slice("github_pr:".length);
  const match = /^https:\/\/github\.com\/([^/]+)\/([^/]+)\/pull\/\d+$/.exec(url);
  if (!match) return null;
  const [, owner, repo] = match;
  if (!GITHUB_OWNER_REPO_RE.test(owner) || !GITHUB_OWNER_REPO_RE.test(repo)) return null;
  return { owner, repo };
}

/** Fail-closed bei fehlenden Voraussetzungen (kein github_pr-Verweis, keine Commit-Range) --
 *  liefert dann reason "not_applicable_*", KEIN ok:false-Fehlschlag, da requiredDevTaskEvidenceV2()
 *  Diff-Evidenz bereits unabhaengig davon erzwingt (siehe present.diff_full oben). Diese Funktion
 *  prueft nur die ZUSAETZLICHE Frage: stimmt der behauptete Diff mit dem echten GitHub-Diff ueberein. */
export async function crossCheckGitHubDiff(bundle: EvidenceBundle): Promise<GitHubDiffCheckResult> {
  const controller = bundle.controller_evidence;
  if (!controller) return { ok: false, reason: "not_applicable_missing_controller_evidence" };
  const repo = parseGithubPrReference(controller.result_reference);
  if (!repo) return { ok: false, reason: "not_applicable_no_github_pr_reference" };
  const baseCommit = controller.base_commit;
  const resultCommit = controller.repository_state?.result_commit ?? null;
  if (!baseCommit || !resultCommit) return { ok: false, reason: "not_applicable_missing_commit_range" };
  if (!GIT_COMMIT_SHA_RE.test(baseCommit) || !GIT_COMMIT_SHA_RE.test(resultCommit)) {
    return { ok: false, reason: "invalid_commit_sha_format" };
  }
  if (!controller.diff_full_sha256) return { ok: false, reason: "not_applicable_no_diff_full_sha256" };

  const repoSlug = `${repo.owner}/${repo.repo}`;
  const dir = mkdtempSync(path.join(tmpdir(), "alex-verify-github-diff-"));
  try {
    execFileSync("git", ["init", "-q"], { cwd: dir, stdio: "pipe" });
    execFileSync("git", ["remote", "add", "origin", `https://github.com/${repoSlug}.git`], { cwd: dir, stdio: "pipe" });
    execFileSync("git", ["fetch", "-q", "--depth=1", "origin", baseCommit], { cwd: dir, stdio: "pipe" });
    execFileSync("git", ["fetch", "-q", "--depth=1", "origin", resultCommit], { cwd: dir, stdio: "pipe" });
    // .trim() spiegelt exakt gitExec() in repoContributionPipeline.server.ts, das den
    // urspruenglichen `diff --cached HEAD`-Output vor dem Hashen ebenso trimmt -- ohne das wuerde
    // ein reiner Zeilenumbruch-Unterschied jeden echten, unveraenderten Diff faelschlich als
    // "manipuliert" melden.
    const diff = execFileSync("git", ["diff", baseCommit, resultCommit], { cwd: dir, maxBuffer: 200 * 1024 * 1024 }).toString().trim();
    const diffHash = sha256(diff);
    if (diffHash !== controller.diff_full_sha256) {
      return { ok: false, reason: "diff_mismatch", repo: repoSlug, base_commit: baseCommit, result_commit: resultCommit };
    }
    return { ok: true, repo: repoSlug, base_commit: baseCommit, result_commit: resultCommit };
  } catch (error) {
    return { ok: false, reason: `git_operation_failed:${error instanceof Error ? error.message : String(error)}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Merkle-Verifikation nach RFC 6962 §2.1, identische Definition wie observer-service/src/merkle.ts
// (kein Shared Import, siehe Datei-Header). Nur die Pruef-Richtung (Audit-Path -> Root) wird hier
// gebraucht, nicht der Aufbau des Baums selbst.
interface ObserverAuditPathStep { hash: string; position: "left" | "right"; }
function observerLeafHash(data: Buffer): Buffer {
  return createHash("sha256").update(Buffer.concat([Buffer.from([0x00]), data])).digest();
}
function verifyObserverAuditPath(leaf: Buffer, path: ObserverAuditPathStep[], expectedRootHex: string): boolean {
  let acc = leaf;
  for (const step of path) {
    const sibling = Buffer.from(step.hash, "hex");
    const nodePrefix = Buffer.from([0x01]);
    acc = step.position === "left" ? createHash("sha256").update(Buffer.concat([nodePrefix, sibling, acc])).digest()
                                     : createHash("sha256").update(Buffer.concat([nodePrefix, acc, sibling])).digest();
  }
  return acc.toString("hex") === expectedRootHex;
}

export interface ObserverCheckResult {
  ok: boolean;
  reason?: string;
  anchor_status?: "pending" | "bitcoin_confirmed";
}

/** Fragt den Observer-Dienst FRISCH und DIREKT ab (nie nur die im Bundle mitgelieferte Kopie
 *  vertrauen -- sonst waere die Pruefung zirkulaer, derselbe Designfehler, der bei
 *  crossCheckTrustAnchor() in Phase 1.2 schon einmal vor dem Commit korrigiert wurde). Prueft den
 *  Merkle-Inclusion-Proof selbst nach. Der OpenTimestamps-Anker-Status (`pending`/
 *  `bitcoin_confirmed`) wird dagegen vom Observer UEBERNOMMEN, nicht durch eine zusaetzliche
 *  OTS-Kryptopruefung hier bestaetigt -- vermeidet eine zweite `opentimestamps`-Abhaengigkeit mit
 *  denselben bekannten CVEs (siehe observer-service/README.md) in diesem staerker
 *  sicherheitskritischen, oeffentlich verteilten Werkzeug. */
export async function crossCheckObserverReceipt(bundle: EvidenceBundle): Promise<ObserverCheckResult> {
  if (!bundle.observer_receipt) return { ok: false, reason: "not_applicable_no_observer_receipt" };
  const { observer_receipt, ...withoutObserverReceipt } = bundle;
  const expectedBundleSha256 = sha256(JSON.stringify(withoutObserverReceipt));

  let response: Response;
  try {
    response = await fetch(`${observer_receipt.observer_url.replace(/\/$/, "")}/observer/receipt/${encodeURIComponent(bundle.bundle_id)}`);
  } catch (error) {
    return { ok: false, reason: `observer_unreachable:${error instanceof Error ? error.message : String(error)}` };
  }
  if (!response.ok) return { ok: false, reason: `observer_http_${response.status}` };
  const data: any = await response.json();
  if (!data.found) return { ok: false, reason: "observer_does_not_know_bundle" };
  if (data.bundle_sha256 !== expectedBundleSha256) return { ok: false, reason: "bundle_sha256_mismatch" };
  if (!data.inclusion || !data.anchor) return { ok: false, reason: "not_yet_anchored" };

  const leaf = observerLeafHash(Buffer.from(JSON.stringify({
    bundle_id: bundle.bundle_id,
    bundle_sha256: data.bundle_sha256,
    run_id: bundle.run_id,
    executed_at: bundle.executed_at,
    received_at: data.received_at,
  })));
  const inclusionOk = verifyObserverAuditPath(leaf, data.inclusion.audit_path, data.inclusion.root_hash);
  if (!inclusionOk) return { ok: false, reason: "inclusion_proof_invalid" };

  return { ok: true, anchor_status: data.anchor.status };
}

// Bauanleitung Evidence-Standard, Punkt 3 (06.09.2026): "Proof Policies" -- Mindestbeweislage vor
// einer als "gated" markierten Aktion. Siehe spec/policies/README.md fuer das Format. Identische
// Kopie in server/services/mrtb/evidenceBundle.server.ts (kein Shared Import, siehe Datei-Header
// oben). `verifierChecks` MUSS aus einer echten, hier selbst durchgefuehrten Pruefung stammen
// (crossCheckObserverReceipt() etc. unten in main()) -- niemals eine blosse Behauptung aus dem
// Bundle selbst, sonst waere "independent_witness" nur Selbstauskunft (spec/INVARIANTS.md
// Invariante 1).
export interface ProofPolicy {
  policy_id: string;
  gates_action: string;
  capability?: string;
  description?: string;
  requires: {
    outcome?: EvidenceBundle["outcome"];
    claim_ladder_min?: ClaimLadder;
    human_approval?: "required";
    no_unsupported_required_claims?: boolean;
    independent_witness?: "required";
  };
}

export interface ProofPolicyEvaluation {
  policy_id: string;
  gates_action: string;
  allowed: boolean;
  blocked_by: string[];
  evaluated: Record<string, { required: unknown; satisfied: boolean }>;
}

export function evaluateProofPolicy(
  policy: ProofPolicy,
  bundle: EvidenceBundle,
  context: { effectiveClaimLadder: ClaimLadder; verifierChecks: Record<string, string> },
): ProofPolicyEvaluation {
  const evaluated: Record<string, { required: unknown; satisfied: boolean }> = {};
  const blockedBy: string[] = [];
  const record = (name: string, required: unknown, satisfied: boolean) => {
    evaluated[name] = { required, satisfied };
    if (!satisfied) blockedBy.push(name);
  };
  const { requires } = policy;
  if (requires.outcome !== undefined) {
    record("outcome", requires.outcome, bundle.outcome === requires.outcome);
  }
  if (requires.claim_ladder_min !== undefined) {
    record("claim_ladder_min", requires.claim_ladder_min, claimLadderRank(context.effectiveClaimLadder) >= claimLadderRank(requires.claim_ladder_min));
  }
  if (requires.human_approval === "required") {
    record("human_approval", "required", bundle.approval_attestation_required === true);
  }
  if (requires.no_unsupported_required_claims === true) {
    record("no_unsupported_required_claims", true, !assessClaimEvidenceRefs(bundle).some(claim => claim.required && !claim.supported));
  }
  if (requires.independent_witness === "required") {
    record("independent_witness", "required", context.verifierChecks.observer_inclusion === "ok");
  }
  return { policy_id: policy.policy_id, gates_action: policy.gates_action, allowed: blockedBy.length === 0, blocked_by: blockedBy, evaluated };
}

async function main() {
  const bundlePath = process.argv[2];
  if (!bundlePath) {
    console.error("Usage: verify <bundle.json> [controller-key.pem] [approval-key.pem] [validation.json evidence-key.pem review.json reviewer-key.pem]");
    console.error("  Ohne controller-key.pem: der Trust-Anchor wird automatisch gegen mehrere unabhaengige Kanaele geprueft.");
    process.exitCode = 1;
    return;
  }

  const bundle = JSON.parse(readFileSync(bundlePath, "utf-8")) as EvidenceBundle;
  let trustedPublicKey = process.argv[3] ? readFileSync(process.argv[3], "utf-8") : undefined;
  let trustedApprovalPublicKey = process.argv[4] ? readFileSync(process.argv[4], "utf-8") : undefined;

  if (!trustedPublicKey && isDevTaskV2Schema(bundle.schema_version)) {
    const consensus = await crossCheckTrustAnchor("evidence_package");
    printConsensus("evidence_package", consensus);
    if (consensus.agreed_public_key_pem) trustedPublicKey = consensus.agreed_public_key_pem;
  }
  if (!trustedApprovalPublicKey && bundle.approval_attestation_required && bundle.approval_attestation) {
    const consensus = await crossCheckTrustAnchor("human_approval");
    printConsensus("human_approval", consensus);
    if (consensus.agreed_public_key_pem) trustedApprovalPublicKey = consensus.agreed_public_key_pem;
  }

  const result = verifyBundleObject(bundle, trustedPublicKey, trustedApprovalPublicKey);
  const reading = buildCustomerReadingViewDe(bundle, trustedPublicKey, trustedApprovalPublicKey);
  if (reading.integrity === "checked") {
    for (const section of reading.sections) {
      console.log(`\n${section.question}`);
      for (const line of section.lines) console.log(`  ${line.warning ? "ACHTUNG: " : ""}${line.text}`);
    }
  }

  if (!result.ok) {
    console.error(`❌ Bundle verification failed: ${result.reason}`);
    process.exitCode = 2;
    return;
  }

  // Bauanleitung 1.4, Rest (05.09.2026): harte Zusatzpruefung, kein reines Konsistenz-Signal wie
  // ci_result (das der Controller selbst signiert) -- hier fragt der Verifier GitHub UNABHAENGIG
  // vom Controller. ALEX_VERIFY_SKIP_GITHUB_DIFF=1 als bewusster Not-Ausweg fuer
  // Offline-/CI-Umgebungen ohne Netzwerk -- druckt dann eine unuebersehbare Warnung statt
  // stillschweigend zu bestehen.
  if (process.env.ALEX_VERIFY_SKIP_GITHUB_DIFF === "1") {
    console.warn("   ⚠ GitHub-Diff-Gegenpruefung uebersprungen (ALEX_VERIFY_SKIP_GITHUB_DIFF=1) -- Diff-Aussage ist NICHT unabhaengig bestaetigt.");
  } else {
    const diffCheck = await crossCheckGitHubDiff(bundle);
    if (diffCheck.ok) {
      console.log(`   GitHub-Diff-Gegenpruefung: signierter Diff stimmt mit github.com/${diffCheck.repo}@${diffCheck.base_commit}..${diffCheck.result_commit} ueberein.`);
    } else if (diffCheck.reason?.startsWith("not_applicable_")) {
      console.log(`   GitHub-Diff-Gegenpruefung uebersprungen (${diffCheck.reason}) -- kein pruefbarer github_pr-Verweis im Bundle.`);
    } else {
      console.error(`❌ GitHub-Diff-Gegenpruefung fehlgeschlagen: ${diffCheck.reason}`);
      process.exitCode = 5;
      return;
    }
  }

  // checks: Rohbefunde je Zusatzpruefung, unabhaengig davon ob sie fuer dieses Bundle ueberhaupt
  // zutreffen -- "not_applicable" ist kein Fehlschlag. verifiedClaimLadder wird DARAUS am Ende
  // abgeleitet, niemals umgekehrt (Leitprinzip der Bauanleitung: die Ladder darf nur steigen, wenn
  // der Verifier den Nachweis tatsaechlich selbst erzwingt).
  const checks: Record<string, string> = { signature: "ok", hash_chain: "ok" };
  let reviewerPathReachedL3 = false;

  if (process.argv[5]) {
    const validationBytes = readFileSync(process.argv[5]);
    const validation = JSON.parse(validationBytes.toString("utf8")) as ValidationAttestationV1;
    const evidenceKey = process.argv[6] ? readFileSync(process.argv[6], "utf8") : "";
    const expectedCommit = bundle.controller_evidence?.repository_state?.result_commit ?? "";
    const validationResult = verifyValidationAttestation(validation, evidenceKey, expectedCommit);
    if (!validationResult.ok) { console.error(`Validation verification failed: ${validationResult.reason}`); process.exitCode = 3; return; }
    if (process.argv[7]) {
      const bundleBytes = readFileSync(bundlePath); const review = JSON.parse(readFileSync(process.argv[7], "utf8")) as ReviewerAttestationV1;
      const reviewerKey = process.argv[8] ? readFileSync(process.argv[8], "utf8") : "";
      const reviewResult = verifyReviewerAttestation(review, reviewerKey, bundleBytes, validationBytes);
      if (!reviewResult.ok) { console.error(`Reviewer verification failed: ${reviewResult.reason}`); process.exitCode = 4; return; }
      console.log("   independent validation + reviewer signature verified (Claim-Ladder=L3)");
      checks.independent_reviewer = "ok";
      reviewerPathReachedL3 = true;
    } else {
      console.log("   independent validation verified; reviewer signature missing (Claim-Ladder remains L2)");
      checks.independent_reviewer = "validation_only";
    }
  }

  console.log(`✅ Bundle ${bundle.bundle_id} verified. Capability=${bundle.capability}, signed Claim-Ladder=${bundle.claim_ladder}`);

  // Bauanleitung "Geschichtete Evidence-Architektur" Punkt 1, DoD (05.09.2026): explizite
  // Verifier-Ausgabezeile fuer Contract-Hash/Scope/Erfolgskriterien. contract_bound_ok/scope_ok
  // sind unabhaengig aus den signierten Trace-Events nachgerechnet (nicht nur behauptet);
  // acceptance_assertions ist bereits Teil des signierten customer_evidence (gleiches
  // Vertrauensmodell wie open_risks/denied -- vom pruefenden Controller berechnet und signiert,
  // hier nicht nochmal unabhaengig neu abgeleitet).
  if (bundle.capability === DEVTASK_EXECUTION_CAPABILITY) {
    const hasContractBound = bundle.trace_events.some((e) => e.startsWith(DEVTASK_CONTRACT_BOUND_PREFIX));
    const scopeViolationCount = bundle.trace_events.filter((e) => e.startsWith(DEVTASK_SCOPE_VIOLATION_PREFIX)).length;
    const assertions = bundle.customer_evidence?.acceptance_assertions;
    const assertionText = assertions === undefined
      ? "nicht geprueft (kein CI-Abgleich in diesem Bundle)"
      : assertions.length === 0
        ? "keine definiert"
        : `${assertions.filter(a => a.satisfied === true).length}/${assertions.filter(a => a.satisfied !== null).length} erfuellt`;
    console.log(`   Contract-Hash geprueft: ${hasContractBound ? "ja" : "nein"}. Scope-Verstoesse: ${scopeViolationCount === 0 ? "keine" : scopeViolationCount}. Erfolgskriterien: ${assertionText}.`);

    // Bauanleitung "Geschichtete Evidence-Architektur" Punkt 2, DoD (05.09.2026): negative_claims
    // werden -- anders als acceptance_assertions oben -- direkt aus den signierten trace_events
    // unabhaengig nachgerechnet (gleiches Vertrauensmodell wie Contract-Hash/Scope-Verstoesse), nicht
    // aus dem vom Controller vorab bewerteten customer_evidence uebernommen. strength wird explizit
    // ausgeschrieben, damit "policy_derived" (informativ) nie wie "observed"/"attested"
    // (ladder-relevant) aussieht -- DoD-Anforderung "im Verifier-Output klar unterscheidbar".
    const negativeClaims = bundle.trace_events
      .map((e) => parseDevTaskEvent<DevTaskNegativeClaimTraceEvent>(e, DEVTASK_NEGATIVE_CLAIM_PREFIX))
      .filter((v): v is DevTaskNegativeClaimTraceEvent => v !== null);
    if (negativeClaims.length > 0) {
      const independent = negativeClaims.filter((c) => c.strength !== "policy_derived");
      const independentFailed = independent.filter((c) => c.result === false).length;
      const policyDerivedCount = negativeClaims.length - independent.length;
      console.log(`   Negative Claims: ${independent.length} observed/attested (${independentFailed === 0 ? "alle bestanden, ladder-relevant" : independentFailed + " fehlgeschlagen -- blockiert"}), ${policyDerivedCount} policy_derived (informativ, kein Ladder-Einfluss).`);
      for (const c of negativeClaims) {
        console.log(`     - ${c.claim}: ${c.result ? "bestanden" : "NICHT bestanden"} [${c.strength}] (${c.verified_by})`);
      }
    }
  }

  const diffEvidence = bundle.trace_events
    .map((e) => parseDevTaskEvent<DevTaskDiffEvidenceTraceEvent>(e, DEVTASK_DIFF_EVIDENCE_PREFIX))
    .find(Boolean);
  if (diffEvidence) {
    console.log(`   diff_stat sha256=${diffEvidence.diff_stat_sha256}`);
    if (diffEvidence.diff_full_sha256) {
      console.log(`   full diff sha256=${diffEvidence.diff_full_sha256} (scope: ${diffEvidence.scope})`);
    } else {
      console.log(`   (scope: ${diffEvidence.scope} -- no full-diff hash on this bundle)`);
    }
  }

  if (bundle.rfc3161_timestamp) {
    const tsResult = verifyRfc3161Binding(bundle);
    if (tsResult.ok) {
      console.log(`   RFC-3161 timestamp bound correctly: gen_time=${bundle.rfc3161_timestamp.gen_time}, tsa=${bundle.rfc3161_timestamp.tsa_url}`);
      checks.rfc3161_binding = "ok";
      const chainResult = verifyRfc3161TsaChain(bundle.rfc3161_timestamp);
      if (chainResult.ok) {
        console.log("   RFC-3161 TSA signature + certificate chain verified against pinned FreeTSA root CA (chain_verified=true).");
        checks.rfc3161_chain = "ok";
      } else {
        console.warn(`   ⚠ RFC-3161 timestamp bound, but TSA signature/chain NOT verified: ${chainResult.reason} -- ignoring it, bundle verdict above is unaffected.`);
        checks.rfc3161_chain = chainResult.reason ?? "failed";
      }
    } else {
      console.warn(`   ⚠ RFC-3161 timestamp present but ${tsResult.reason} -- ignoring it, bundle verdict above is unaffected`);
      checks.rfc3161_binding = tsResult.reason ?? "failed";
    }
  } else {
    checks.rfc3161_binding = "not_applicable_no_timestamp";
  }

  if (bundle.observer_receipt) {
    const observerResult = await crossCheckObserverReceipt(bundle);
    if (observerResult.ok) {
      console.log(`   Observer bestaetigt Aufnahme (${bundle.observer_receipt.observer_url}), Anker-Status: ${observerResult.anchor_status}.`);
      checks.observer_inclusion = "ok";
      checks.observer_anchor = observerResult.anchor_status ?? "unknown";
    } else {
      console.warn(`   ⚠ Observer-Quittung vorhanden, aber NICHT bestaetigt: ${observerResult.reason} -- ignoriert, Urteil oben bleibt unveraendert.`);
      checks.observer_inclusion = observerResult.reason ?? "failed";
    }
  } else {
    checks.observer_inclusion = "not_applicable_no_observer_receipt";
  }

  // spec/INVARIANTS.md: Nur die eigenstaendige, signierte Reviewer-Attestation bindet Bundle
  // und unabhaengige Validation semantisch. RFC-3161 und Observer belegen Integritaet/Zeit/Inklusion,
  // ergeben aber auch zusammen keine unabhaengige Wiederholung der behaupteten Arbeit.
  const baseClaimLadder = result.verified_claim_ladder ?? bundle.claim_ladder;
  const verifiedClaimLadder = reviewerPathReachedL3 && baseClaimLadder === "L2" ? "L3" : baseClaimLadder;

  // 05.09.2026: die fruehere "verified"-Zeile (oben, vor diesen Zusatzpruefungen gedruckt) zeigte
  // nur signed_claim_ladder -- wer nur die erste Zeile liest, sah nie ob dieser Lauf tatsaechlich
  // auf L3 hochgestuft hat. verified_claim_ladder stand bis jetzt nur versteckt im JSON-Block ganz
  // unten. Diese Zeile macht das menschenlesbare Ergebnis explizit, ohne die Berechnung zu aendern.
  console.log(
    claimLadderRank(verifiedClaimLadder) > claimLadderRank(bundle.claim_ladder)
      ? `   Verifizierte Claim-Ladder dieses Laufs: ${verifiedClaimLadder} (hochgestuft gegenueber dem signierten ${bundle.claim_ladder})`
      : claimLadderRank(verifiedClaimLadder) < claimLadderRank(bundle.claim_ladder)
      ? `   Verifizierte Claim-Ladder dieses Laufs: ${verifiedClaimLadder} (herabgestuft gegenueber dem signierten ${bundle.claim_ladder} -- frueherer, groeberer Berechnungsstand)`
      : `   Verifizierte Claim-Ladder dieses Laufs: ${verifiedClaimLadder} (keine Aenderung gegenueber dem signierten Wert)`
  );

  // Bauanleitung Evidence-Standard, Punkt 3 (06.09.2026): Proof-Policy-Gate, optional per
  // ALEX_VERIFY_POLICY_FILE. Laeuft NACH allen obigen Pruefungen, damit `checks` (insbesondere
  // observer_inclusion, echt live gegengecheckt oben) und verifiedClaimLadder bereits final
  // feststehen -- die Policy darf nur auf tatsaechlich vom Verifier selbst erhobenen Fakten
  // urteilen, nie auf blossen Bundle-Behauptungen (Invariante 1).
  let proofPolicyResult: ProofPolicyEvaluation | null = null;
  if (process.env.ALEX_VERIFY_POLICY_FILE) {
    const policy = JSON.parse(readFileSync(process.env.ALEX_VERIFY_POLICY_FILE, "utf-8")) as ProofPolicy;
    proofPolicyResult = evaluateProofPolicy(policy, bundle, { effectiveClaimLadder: verifiedClaimLadder, verifierChecks: checks });
    if (proofPolicyResult.allowed) {
      console.log(`\n✅ Proof-Policy '${proofPolicyResult.policy_id}' erfuellt -- gated action '${proofPolicyResult.gates_action}' ist erlaubt.`);
    } else {
      console.error(`\n⛔ Proof-Policy '${proofPolicyResult.policy_id}' NICHT erfuellt -- gated action '${proofPolicyResult.gates_action}' BLOCKIERT. Fehlende Bedingungen: ${proofPolicyResult.blocked_by.join(", ")}`);
    }
  }

  console.log("");
  console.log(JSON.stringify({ signed_claim_ladder: bundle.claim_ladder, verified_claim_ladder: verifiedClaimLadder, checks, proof_policy: proofPolicyResult }, null, 2));

  if (proofPolicyResult && !proofPolicyResult.allowed) {
    process.exitCode = 6;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => { console.error(error); process.exit(1); });
}

// Point 4: display projection, never a second signed summary or a new ladder calculation.
// Keep identical in server and standalone. The existing customer_summary remains byte-stable.
export interface CustomerReadingLine { text: string; sources: string[]; warning?: boolean; }
export interface CustomerReadingView {
  integrity: "checked" | "rejected";
  reason?: string;
  bundle_id: string;
  sections: { question: string; lines: CustomerReadingLine[] }[];
}

export function buildCustomerReadingViewDe(
  bundle: EvidenceBundle, trustedPublicKey?: string, trustedApprovalPublicKey?: string,
): CustomerReadingView {
  const rejected = (reason: string): CustomerReadingView => ({
    integrity: "rejected", reason, bundle_id: bundle.bundle_id, sections: [],
  });
  try {
    const verification = verifyBundleObject(bundle, trustedPublicKey, trustedApprovalPublicKey);
    // The verifier's final outcome rejection is reached ONLY after signature, chain and
    // consistency checks. Failed/inconclusive evidence must remain readable as such.
    if (!verification.ok && verification.reason !== "non_verified_outcome:failed" &&
        verification.reason !== "non_verified_outcome:inconclusive") return rejected(verification.reason ?? "verification_failed");
    if (!isDevTaskV2Schema(bundle.schema_version) || bundle.capability !== DEVTASK_EXECUTION_CAPABILITY || !bundle.controller_evidence) {
      return rejected("unsupported_reading_schema");
    }
    const controller = bundle.controller_evidence;
    const sections: CustomerReadingView["sections"] = [
      { question: "Was wurde erlaubt?", lines: [] },
      { question: "Was wurde getan?", lines: [] },
      { question: "Was wurde nicht getan?", lines: [] },
      { question: "Warum darf ich dem Ergebnis vertrauen?", lines: [] },
    ];
    const add = (section: number, text: string, sources: string[], warning = false) => {
      sections[section].lines.push({ text, sources, ...(warning ? { warning: true } : {}) });
    };
    const entries = (prefix: string) => bundle.trace_events.flatMap((event, index) => {
      if (!event.startsWith(prefix)) return [];
      const value = JSON.parse(event.slice(prefix.length));
      if (!value || typeof value !== "object") throw new Error("invalid_reading_event");
      return [{ value, source: `/trace_events/${index}` }];
    });
    const ownEntries = (prefix: string) => entries(prefix).filter(({ value }) =>
      value.task_id === controller.task_id && value.attempt_number === controller.attempt_number);
    const snapshot = controller.contract_snapshot;
    const contractSource = "/controller_evidence/contract_snapshot";
    if (snapshot) {
      if (typeof snapshot.rawText !== "string" || !Array.isArray(snapshot.acceptanceCriteria)) return rejected("invalid_contract_snapshot");
      add(0, `Eingefrorener Auftrag (Originaltext): ${snapshot.rawText}`, [contractSource + "/rawText"]);
      for (const [index, criterion] of snapshot.acceptanceCriteria.entries()) {
        if (typeof criterion !== "string") return rejected("invalid_contract_snapshot");
        add(0, `Vereinbartes Erfolgskriterium: ${criterion}`, [contractSource + `/acceptanceCriteria/${index}`]);
      }
      if (typeof snapshot.protectExistingTests === "boolean") add(0,
        snapshot.protectExistingTests ? "Bestehende Tests sollten geschuetzt bleiben." : "Schutz bestehender Tests war nicht angefordert.",
        [contractSource + "/protectExistingTests"]);
      add(0, "Der eingefrorene Auftrag stimmt mit seinem signierten Pruefwert ueberein. Freitext ist keine maschinell gepruefte Liste erlaubter Aktionen.",
        [contractSource, ...ownEntries(DEVTASK_CONTRACT_BOUND_PREFIX).map(e => e.source)]);
    } else {
      add(0, "Contract-Pruefung des Auftragstexts in diesem Bundle nicht enthalten.", [contractSource], true);
      if (bundle.customer_evidence) add(0, `Auftrag laut signierter Zusammenfassung: ${bundle.customer_evidence.brief.raw_text}`,
        ["/customer_evidence/brief/raw_text"]);
    }
    const approval = ownEntries(DEVTASK_HUMAN_APPROVAL_PREFIX);
    if (approval.length) for (const entry of approval) add(0,
      `Freigabe protokolliert von: ${entry.value.actor_id}.`, [entry.source]);
    else add(0, "Keine Freigabe in diesem Bundle protokolliert.", ["/trace_events"]);

    for (const { value, source } of ownEntries(DEVTASK_OUTCOME_PREFIX)) {
      const states: Record<string, string> = { COMPLETED: "abgeschlossen", ABORTED: "abgebrochen", FAILED: "fehlgeschlagen" };
      add(1, `Protokollierter Ausfuehrungsstatus: ${states[value.outcome] ?? value.outcome}.`, [source]);
    }
    const outcomes = { verified: "Die im Bundle verlangten Nachweise sind erfuellt.", failed: "Der Lauf erfuellt die Nachweisanforderungen nicht.", inconclusive: "Die Nachweise reichen fuer ein abschliessendes Ergebnis nicht aus." };
    add(1, outcomes[bundle.outcome], ["/outcome", "/required_evidence"], bundle.outcome !== "verified");
    if (controller.result_reference) add(1, `Protokolliertes Ergebnis: ${controller.result_reference}`, ["/controller_evidence/result_reference"]);
    const repository = controller.repository_state;
    if (repository) for (const [index, file] of repository.changed_files.entries()) {
      const labels: Record<string, string> = { A: "hinzugefuegt", M: "geaendert", D: "entfernt" };
      add(1, `Laut signiertem Dateinachweis ${labels[file.status] ?? file.status}: ${file.path}`,
        [`/controller_evidence/repository_state/changed_files/${index}`]);
    }
    else add(1, "Dateiaenderungs-Pruefung in diesem Bundle nicht enthalten.", ["/controller_evidence/repository_state"], true);
    for (const { value, source } of ownEntries(DEVTASK_CI_RESULT_PREFIX)) {
      const states: Record<string, string> = { success: "erfolgreich", failure: "fehlgeschlagen", pending: "noch offen", none: "kein Ergebnis", neutral: "neutral", skipped: "uebersprungen", other: "nicht eindeutig" };
      add(1, `Protokollierte externe Tests insgesamt: ${states[value.conclusion] ?? value.conclusion}.`, [source]);
      for (const check of value.checks ?? []) add(1, `Protokollierter Check ${check.name}: ${states[check.conclusion] ?? check.conclusion}.`, [source], check.conclusion !== "success");
    }
    const assertions = bundle.customer_evidence?.acceptance_assertions;
    if (assertions === undefined) add(1, "Erfolgskriterien-Pruefung in diesem Bundle nicht enthalten.", ["/customer_evidence/acceptance_assertions"], true);
    else if (!assertions.length) add(1, "Keine maschinell pruefbaren Erfolgskriterien im Bundle aufgefuehrt.", ["/customer_evidence/acceptance_assertions"]);
    else for (const [index, assertion] of assertions.entries()) add(1,
      `Kriterium laut signierter Auswertung: ${assertion.description} ? ${assertion.satisfied === null ? "nicht maschinell pruefbar" : assertion.satisfied ? "erfuellt" : "nicht erfuellt"}.`,
      [`/customer_evidence/acceptance_assertions/${index}`], assertion.satisfied !== true);

    const negative = ownEntries(DEVTASK_NEGATIVE_CLAIM_PREFIX);
    const claimLabels: Record<string, string> = {
      no_network_outside_scope: "Kein Netzwerkzugriff ausserhalb der erlaubten Grenzen",
      no_secret_access: "Kein Zugriff auf geheime Zugangsdaten",
      no_write_outside_allowlist: "Keine Schreibzugriffe ausserhalb der erlaubten Pfade",
    };
    const strengths: Record<string, string> = {
      policy_derived: "Aus der Konfiguration abgeleitet; nicht durch Laufzeitbeobachtung oder unabhaengig bestaetigt",
      observed: "Aus aufgezeichnetem Laufzeitverhalten abgeleitet; vom Controller berichtet",
      attested: "Im Nachweis als unabhaengig bestaetigt eingestuft; diese Bestaetigung wird hier nicht separat nachgeprueft",
      independently_witnessed: "Durch ein eigenstaendiges Artefakt einer unabhaengigen Instanz belegt",
      cryptographically_verified: "Kryptographische Bindung und Vertrauenskette wurden vom Verifier selbst geprueft",
    };
    for (const claim of Object.keys(claimLabels)) if (!negative.some(e => e.value.claim === claim)) {
      add(2, `${claimLabels[claim]}: Pruefung in diesem Bundle nicht enthalten.`, ["/trace_events"], true);
    }
    for (const { value, source } of negative) {
      if (typeof value.result !== "boolean" || !Object.hasOwn(strengths, value.strength) || typeof value.verified_by !== "string" || typeof value.claim !== "string") return rejected("invalid_negative_claim");
      add(2, `${claimLabels[value.claim] ?? value.claim}: ${value.result ? "laut Nachweis bestaetigt" : "NICHT bestaetigt"}. ${strengths[value.strength]}. Nachweisursprung: ${value.verified_by}.`,
        [source], !value.result);
    }
    // Handoff filtering is not a contract or sandbox violation (see point 1).
    for (const [index, denied] of (bundle.customer_evidence?.denied ?? []).entries()) add(2,
      `Bei der Dateiuebergabe abgelehnt: ${denied.path} (${denied.reason}). Das allein belegt keinen Auftragsverstoss.`,
      [`/customer_evidence/denied/${index}`]);

    const ladderMeaning: Record<string, string> = {
      L0: "Ein erfolgreich nachgewiesenes Ergebnis liegt nicht vor.",
      L1: "Die verlangten Bundle-Nachweise sind erfuellt; die Freigabe ist nicht an einen Passkey gebunden.",
      L2: "Die verlangten Bundle-Nachweise sind erfuellt. Das allein ist keine unabhaengige Wiederholung der Arbeit.",
    };
    // Der signierte Wert kann aus einer frueheren, groeberen Berechnung stammen (siehe
    // claimLadderRank()-Kommentar oben) -- angezeigt wird immer die heute tatsaechlich
    // nachvollziehbare (ggf. niedrigere) Stufe, nie ein hoeherer, nur behaupteter Wert.
    const effectiveLadder = verification.verified_claim_ladder ?? bundle.claim_ladder;
    add(3, ladderMeaning[effectiveLadder] ?? "Fuer diese Nachweisstufe ist hier keine Erklaerung hinterlegt.", ["/claim_ladder"]);
    add(3, `Nachweisstufe dieses Bundles: ${effectiveLadder}. Signatur, Pruefwertkette und abgeleitetes Ergebnis wurden gegen die hinterlegten Vertrauensschluessel geprueft.`,
      ["/claim_ladder", "/signature", "/trace_hash_chain", "/outcome"]);
    if (effectiveLadder !== bundle.claim_ladder) add(3,
      `Hinweis: Der im Bundle signierte Wert (${bundle.claim_ladder}) stammt aus einer frueheren, weniger differenzierten Berechnung. Nach heutigem, praeziserem Massstab bestaetigt sich nur ${effectiveLadder}.`,
      ["/claim_ladder"], true);
    add(3, "Diese Ansicht prueft Bundle-Konsistenz. Sie fuehrt die Arbeit nicht erneut aus und bestaetigt weder fachliche Richtigkeit noch externe Observer-/Reviewer-Nachweise. Dafuer ist der unabhaengige Verifier mit seinen Zusatzpruefungen erforderlich.",
      ["/required_evidence", "/claim_ladder"]);
    // 06.09.2026: reine Vorhandensein-Aussage, keine Live-Nachpruefung (die macht bewusst nur der
    // unabhaengige Verifier ueber crossCheckObserverReceipt() -- Satz direkt darueber). Macht eine
    // bereits bestehende, aber bisher nur im CLI-Verifier sichtbare Eigenschaft (separater Host,
    // separater Signierschluessel) auch in der Nicht-Entwickler-Leseschicht benennbar.
    if (bundle.observer_receipt) add(3,
      `Zusaetzlich von einem unabhaengigen Beobachter auf einem separaten Server mit eigenem Signierschluessel aufgezeichnet (${bundle.observer_receipt.observer_url}). Ob der Beobachter das heute noch live bestaetigt, prueft nur der unabhaengige Verifier, nicht diese Ansicht.`,
      ["/observer_receipt"]);
    else add(3, "Kein unabhaengiger Zweit-Server-Beleg (Observer) fuer diesen Lauf vorhanden.", ["/observer_receipt"], true);
    const scope = ownEntries(DEVTASK_SCOPE_VIOLATION_PREFIX);
    for (const { value, source } of scope) add(3, `Grenzverstoss protokolliert: ${value.detail} (${value.violation_type}).`, [source], true);
    const contradictions = entries(DEVTASK_CONTRADICTION_PREFIX);
    if (!contradictions.length) add(3, "Widerspruchs-Pruefung in diesem Bundle nicht enthalten; keine Aussage ueber Widerspruchsfreiheit.", ["/trace_events"], true);
    for (const { value, source } of contradictions) {
      if (typeof value.resolved !== "boolean" || typeof value.subject !== "string" || typeof value.property !== "string") return rejected("invalid_contradiction");
      add(3, `${value.resolved ? "Als aufgeloest protokollierter" : "OFFENER"} Widerspruch: ${value.subject} / ${value.property}. Vorheriger Nachweis: ${value.previous_bundle_id}; aktueller Nachweis: ${value.current_bundle_id}. Stand: ${value.detected_at}.`,
        [source], !value.resolved);
    }
    const risks = bundle.customer_evidence?.open_risks;
    if (risks === undefined) add(3, "Pruefung offener Risiken in diesem Bundle nicht enthalten.", ["/customer_evidence/open_risks"], true);
    else if (!risks.length) add(3, "Keine offenen Risiken im Bundle erfasst; das bedeutet nicht Risikofreiheit.", ["/customer_evidence/open_risks"]);
    else for (const [index, risk] of risks.entries()) add(3,
      `Offenes Risiko laut Nachweis: ${risk.description}${risk.recommended_action ? ` Empfohlener naechster Schritt: ${risk.recommended_action}` : ""}`,
      [`/customer_evidence/open_risks/${index}`], true);
    return { integrity: "checked", bundle_id: bundle.bundle_id, sections };
  } catch {
    return rejected("invalid_bundle_or_reading_data");
  }
}
