# Test B — Fremde Umgebung

**Zuletzt bearbeitet:** 2026-09-06
**Von:** MERIDIAN

**Ergebnis:** bestanden.

- Zeitpunkt: `2026-09-06T16:52:40Z`
- Entwicklung: Windows
- Pruefung: separater Hetzner-Host, Ubuntu 26.04 LTS, Linux 7.0.0-22 x86_64
- Laufzeit: Python 3.14.4, OpenSSL 3.5.5
- Verifier-Ausgabe: `VERIFIED`, Exitcode `0`

```text
$ uname -a
Linux ubuntu-8gb-fsn1-1 7.0.0-22-generic #22-Ubuntu SMP PREEMPT_DYNAMIC Mon May 25 15:54:34 UTC 2026 x86_64 GNU/Linux
$ python3 --version
Python 3.14.4
$ openssl version
OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)
$ python3 verify.py demo-pr-38.json trusted-evidence.pem trusted-approval.pem
VERIFIED
```

Noetig war nur der portable Werkzeugsatz. Es gab keine Abhaengigkeit von der
Windows-Entwicklungsmaschine oder deren Node-Modulen.
