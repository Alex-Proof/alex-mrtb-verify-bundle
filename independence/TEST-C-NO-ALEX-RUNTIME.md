# Test C — Kein ALEX-Runtime

**Zuletzt bearbeitet:** 2026-09-06
**Von:** MERIDIAN

**Ergebnis:** bestanden. Produktionsdienst danach wieder vollstaendig gesund.

- Snapshot und Bundle wurden vor dem Stopp gesichert.
- Stopp: `2026-09-06T16:53:58Z`
- `systemctl is-active alex-os` ergab `inactive`
- `curl http://localhost:4000/health` ergab Verbindung abgelehnt
- alle neun Dateien im Hashmanifest ergaben `OK`
- Verifier waehrend des Stillstands: `VERIFIED`
- Neustart: `2026-09-06T16:54:11Z`, systemd `active`
- finaler Healthcheck: HTTP 200, `db_ok:true`, `auth_self_test_ok:true`

```text
TEST_C_STOP_AT=2026-09-06T16:53:58Z
inactive
curl: (7) Failed to connect to localhost port 4000
verify.py: OK
spec/canonicalization-v1.gold.json: OK
spec/devtask.execution@1.0.md: OK
spec/devtask.execution@1.0.schema.json: OK
spec/INVARIANTS.md: OK
trust-anchor-pre-stop.json: OK
demo-pr-38.json: OK
alex-independence-evidence.pem: OK
alex-independence-approval.pem: OK
VERIFIED
TEST_C_RESTARTED_AT=2026-09-06T16:54:11Z
active
```

Der erste Health-Aufruf acht Sekunden nach `systemctl start` war noch zu frueh: systemd
meldete bereits `active`, Port 4000 war noch nicht gebunden. Der Folgecheck nach weiteren
zwoelf Sekunden war gruen. Waehrend der erfolgreichen Verifikation war der ALEX-Prozess
nachweislich vollstaendig gestoppt.
