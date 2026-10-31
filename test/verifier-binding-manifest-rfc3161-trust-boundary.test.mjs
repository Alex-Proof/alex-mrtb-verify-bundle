import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildVerifierBindingManifestV1, verifyVerifierBindingManifestV1, verifyRfc3161Binding, verifyRfc3161TsaChain } from "../dist/verify.js";

// 31.10.2026 (externer Haertungsvorschlag, SaSame @sasame-mcp.bsky.social, Folgefrage nach dem
// adversarial-Test oben): "verify the same valid bundle/token with a trust store that omits the
// FreeTSA root. Derivation + message imprint should pass, then chain trust must fail separately.
// That proves 'valid token' isn't being confused with 'trusted TSA'."
//
// verifyRfc3161TsaChain() prueft die CMS-Signatur UND die Zertifikatskette gegen die fest
// gepinnte FreeTSA-Root (FREETSA_ROOT_CA_PEM in verify.ts, kein konfigurierbarer Trust-Store) --
// es gibt also keinen Parameter, mit dem man "die Root weglassen" koennte. Stattdessen baut dieser
// Test einen ECHTEN, korrekt signierten RFC3161-Token mit einer FREMDEN, selbst erzeugten
// Root-CA: die CMS-Signatur ist intern vollstaendig gueltig (derselbe Code-Pfad, der eine echte
// FreeTSA-Signatur prueft, akzeptiert sie bis zum Kettenvergleich), nur die Ausstellerkette zeigt
// nicht auf FreeTSA. Erzeugt die Zertifikate/den Token zur Laufzeit per System-OpenSSL (`openssl
// req`/`openssl ts`) -- dasselbe Werkzeug, auf das der eigenstaendige Python-Verifier ohnehin schon
// fuer Ed25519 angewiesen ist, keine neue Abhaengigkeitsklasse.
const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const opensslAvailable = !spawnSync("openssl", ["version"], { encoding: "utf8" }).error;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().filter(k => value[k] !== undefined).map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}

// Identischer Aufbau wie syntheticBundleWithoutApproval() in
// verifier-binding-manifest-rfc3161-adversarial.test.mjs: bewusst ohne approval_attestation, sonst
// wuerde dessen bundle_sha256-Bindung (haengt an rfc3161_timestamp, da in der echten Pipeline vor
// der Freigabe angehaengt) jeden Token-Tausch schon eine Ebene vorher abfangen.
function syntheticBundleWithoutApproval() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const run = { task_id: "trust-boundary-src", attempt_number: 1 };
  const contract_snapshot = { rawText: "x", acceptanceCriteria: ["ok"], protectExistingTests: false };
  const repositoryState = { schema_version: "repository-state@1.0", base_commit: "a".repeat(40), result_commit: "b".repeat(40), tree_before_sha256: sha256("before"), tree_after_sha256: sha256("after"), changed_files: [] };
  const traceEvents = [
    `devtask_contract_bound:${JSON.stringify({ ...run, contract_hash: sha256(JSON.stringify(contract_snapshot)), risk_class: "R1" })}`,
    `devtask_attempt_started:${JSON.stringify({ ...run, started_at: "2026-10-31T00:00:00Z" })}`,
    `devtask_execution_context:${JSON.stringify({ ...run, execution_reference: "attempt:1", sandbox_reference: null })}`,
    `devtask_validation:${JSON.stringify({ ...run, validation_status: "passed", validation_reference: "validation:1" })}`,
    `devtask_diff_evidence:${JSON.stringify({ ...run, diff_stat_sha256: sha256("stat"), diff_full_sha256: sha256("diff"), scope: "diff_stat_and_full" })}`,
    `devtask_outcome:${JSON.stringify({ ...run, outcome: "ABORTED", completed_at: "2026-10-31T00:01:00Z" })}`,
  ];
  let prev = "genesis";
  const trace_hash_chain = traceEvents.map(e => (prev = sha256(prev + e)));
  const controller_evidence = {
    producer: "privileged_controller", ...run, base_commit: repositoryState.base_commit, result_reference: null,
    policy_snapshot_sha256: sha256("policy-snapshot"), diff_stat_sha256: sha256("stat"), diff_full: "diff",
    diff_full_sha256: sha256("diff"), execution_reference: "attempt:1", validation_reference: "validation:1",
    approval_reference: null, sandbox_reference: null, sandbox_attestation: null, agent_run_id: null,
    contract_snapshot, repository_state: repositoryState,
  };
  const payload = {
    schema_version: "evidence-package@2.2", spec_version: "devtask.execution@1.0", bundle_id: "trust-boundary-src",
    capability: "devtask.execution@1.0", run_id: "trust-boundary-src:1", claim_ladder: "L0", executed_at: "2026-10-31T00:01:00Z",
    trace_events: traceEvents, trace_hash_chain, outcome: "failed", signer_key_id: `ed25519:${sha256(pem)}`, controller_evidence,
    required_evidence: ["contract", "attempt", "execution_context", "validation", "outcome", "base_commit", "diff_full", "repository_state"],
    approval_attestation_required: false,
  };
  const signature = sign(null, Buffer.from(canonical(payload), "utf8"), privateKey).toString("base64");
  return { bundle: { ...payload, signature, public_key: pem }, pem };
}

function runOpenssl(args) {
  const result = spawnSync("openssl", args, { encoding: "utf8" });
  assert.equal(result.status, 0, `openssl ${args.join(" ")}\n${result.stderr}`);
  return result;
}

/** Baut zur Laufzeit eine eigene, bewusst NICHT FreeTSA-abstammende Root-CA + TSA-Zertifikat
 *  (ECDSA P-384, wie FreeTSAs eigenes echtes Zertifikat -- OpenSSLs PKCS7-TS-Signatur unterstuetzt
 *  kein Ed25519) und laesst damit einen echten, gueltig signierten RFC3161-Token fuer genau den
 *  uebergebenen Digest ausstellen. Liefert die rohen Token-DER-Bytes base64-kodiert, identisch
 *  zum Format des `token_der_base64`-Felds in einem echten Bundle. */
function buildUntrustedRfc3161Token(dir, digestHex) {
  const rootKey = join(dir, "root.key");
  const rootPem = join(dir, "root.pem");
  const tsaKey = join(dir, "tsa.key");
  const tsaCsr = join(dir, "tsa.csr");
  const tsaPem = join(dir, "tsa.pem");
  const tsaExt = join(dir, "tsa_ext.cnf");
  const tsaCnf = join(dir, "tsa.cnf");
  const serialFile = join(dir, "tsaserial");
  const queryFile = join(dir, "query.tsq");
  const tokenFile = join(dir, "token.der");
  const posix = p => p.replace(/\\/g, "/");

  runOpenssl(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", rootKey]);
  runOpenssl(["req", "-x509", "-key", rootKey, "-out", rootPem, "-days", "365", "-sha256",
    "-subj", "/CN=Untrusted Test Root CA/O=NotFreeTSA"]);
  runOpenssl(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", tsaKey]);
  runOpenssl(["req", "-new", "-key", tsaKey, "-out", tsaCsr, "-sha256",
    "-subj", "/CN=Untrusted Fake TSA/O=NotFreeTSA"]);
  writeFileSync(tsaExt, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n");
  runOpenssl(["x509", "-req", "-in", tsaCsr, "-CA", rootPem, "-CAkey", rootKey, "-CAcreateserial",
    "-out", tsaPem, "-days", "365", "-extfile", tsaExt, "-sha256"]);
  writeFileSync(serialFile, "01\n");
  writeFileSync(tsaCnf, [
    "[tsa_section]",
    `serial = ${posix(serialFile)}`,
    "crypto_device = builtin",
    `signer_cert = ${posix(tsaPem)}`,
    `certs = ${posix(rootPem)}`,
    `signer_key = ${posix(tsaKey)}`,
    "signer_digest = sha256",
    "default_policy = 1.2.3.4.5.6.7.8.1",
    "digests = sha256",
    "accuracy = secs:1",
    "clock_precision_digits = 0",
    "ordering = yes",
    "tsa_name = yes",
    "ess_cert_id_chain = no",
    "",
  ].join("\n"));
  // -cert: der Query bittet den TSA-Dienst, sein eigenes Zertifikat (+ Kette) in die Antwort
  // einzubetten -- ohne das findet verifyRfc3161TsaChain() keinen Signer und scheitert mit
  // signer_certificate_not_found statt dem hier gesuchten chain_untrusted.
  runOpenssl(["ts", "-query", "-digest", digestHex, "-sha256", "-no_nonce", "-cert", "-out", queryFile]);
  runOpenssl(["ts", "-reply", "-config", tsaCnf, "-section", "tsa_section",
    "-queryfile", queryFile, "-token_out", "-out", tokenFile]);
  return readFileSync(tokenFile).toString("base64");
}

function pythonCheck(bundle, timestamp) {
  const dir = mkdtempSync(join(tmpdir(), "rfc3161-trust-boundary-py-"));
  const inputPath = join(dir, "input.json");
  writeFileSync(inputPath, JSON.stringify({ bundle, timestamp }), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "d=json.load(open(sys.argv[2],encoding='utf-8'))",
    "bo,br=m.verify_rfc3161_binding(d['bundle'])",
    "co,cr=m.verify_rfc3161_tsa_chain(d['timestamp'])",
    "print(json.dumps({'binding':'ok' if bo else br,'chain':'ok' if co else cr}))",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout.trim());
}

function pythonVerifyManifest(manifest, bundle, key) {
  const dir = mkdtempSync(join(tmpdir(), "rfc3161-trust-boundary-manifest-py-"));
  const inputPath = join(dir, "input.json");
  writeFileSync(inputPath, JSON.stringify({ manifest, bundle, key }), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "d=json.load(open(sys.argv[2],encoding='utf-8'))",
    "ok,reason=m.verify_verifier_binding_manifest_v1(d['manifest'],d['bundle'],d['key'])",
    "print('ok' if ok else reason)",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test("trust boundary: a real, correctly-signed RFC3161 token from an UNTRUSTED root passes binding but fails chain trust", { skip: !opensslAvailable }, () => {
  const { bundle: syntheticBundle, pem } = syntheticBundleWithoutApproval();
  const dir = mkdtempSync(join(tmpdir(), "rfc3161-untrusted-"));
  // syntheticBundle traegt noch kein rfc3161_timestamp/approval_attestation/observer_receipt/
  // epistemic_gate -- der Bindungs-Digest ueber das rohe Bundle ist hier also bereits der exakte
  // Wert, den verifyRfc3161Binding() nach dem Anhaengen zurueckrechnen wird.
  const digest = sha256(JSON.stringify(syntheticBundle));
  const tokenDerBase64 = buildUntrustedRfc3161Token(dir, digest);

  const timestamp = {
    schema_version: "rfc3161-timestamp@1.0",
    tsa_url: "https://untrusted-fake-tsa.example/tsr",
    timestamped_sha256: digest,
    gen_time: new Date().toISOString(),
    token_der_base64: tokenDerBase64,
  };
  const bundle = { ...syntheticBundle, rfc3161_timestamp: timestamp };

  // Message imprint / Bindung: der Token passt wirklich zu GENAU diesem Bundle-Inhalt.
  assert.deepEqual(verifyRfc3161Binding(bundle), { ok: true });

  // Kettenvertrauen: Signer und CMS-Signatur sind echt und intern gueltig, aber niemals von der
  // gepinnten FreeTSA-Root ausgestellt -- "gueltiger Token" darf nicht mit "vertrauter TSA"
  // verwechselt werden.
  const chain = verifyRfc3161TsaChain(timestamp);
  assert.equal(chain.ok, false);
  assert.equal(chain.reason, "chain_untrusted");
  assert.deepEqual(pythonCheck(bundle, timestamp), { binding: "ok", chain: chain.reason });

  // Herleitung bleibt ebenfalls unberuehrt -- am Bundle wurde sonst nichts veraendert.
  const manifest = buildVerifierBindingManifestV1(bundle);
  assert.deepEqual(manifest, buildVerifierBindingManifestV1(bundle));

  const result = verifyVerifierBindingManifestV1(manifest, bundle, pem);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "rfc3161_tsa_chain_untrusted");
  assert.equal(pythonVerifyManifest(manifest, bundle, pem), result.reason);
});
