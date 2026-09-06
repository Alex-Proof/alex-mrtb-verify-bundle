# Test A — Offline

**Zuletzt bearbeitet:** 2026-09-06
**Von:** MERIDIAN

**Ergebnis:** bestanden.

- Umgebung: neuer Linux-Netzwerk-Namespace
- Netzwerkzustand: ausschliesslich Loopback, `lo DOWN`
- Verifier-Ausgabe: `VERIFIED`
- Exitcode: `0`

```text
$ unshare --net ip -brief link
lo               DOWN           00:00:00:00:00:00 <LOOPBACK>
$ unshare --net python3 verify.py demo-pr-38.json trusted-evidence.pem trusted-approval.pem
VERIFIED
```

Noetig waren Verifier, Bundle, beide vorab aus dem Snapshot aufgeloesten PEMs, Python und
OpenSSL. Spec und Invarianten waren zur Auditierbarkeit beigelegt, wurden technisch nicht
eingelesen. Netzwerk, ALEX-Runtime, Node.js, npm und Datenbank wurden nicht benutzt.
