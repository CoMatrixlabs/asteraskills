# Pack Cache

This directory is the runtime cache for intelligence server rule packs.

In local mode (no license token), this directory is empty and analyzers use built-in rules.

In licensed mode, packs are fetched from the server on first scan and cached here:
- `cve.json` — CVE rule pack (NVD feed, SBOM version range rules)
- `cwe.json` — CWE rule pack (taint signatures, taxonomy)
- `attack.json` — ATT&CK rule pack (IoC signatures, sequence correlator rules)
- `policy.json` — Policy rule pack (IaC rules for AWS/GCP/Azure/k8s)
- `framework.json` — Framework rule pack (SOC2, NIST 800-53, CIS 8, ISO 27001 control checks)
- `*.etag` — ETag values for conditional GET requests (HTTP 304 caching)

**Do not commit pack files to source control.** The `.gitignore` excludes all files in this directory except `README.md` and `.gitkeep`.
