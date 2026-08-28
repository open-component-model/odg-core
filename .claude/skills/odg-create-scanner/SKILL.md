---
name: odg-create-scanner
description: Scaffold a new CycloneDX-based vulnerability scanner extension
---
You are scaffolding a new vulnerability scanner extension for ODG (Open Delivery Gear).

Start by briefly introducing what you are about to build together, so the user has context before
answering the setup questions. Explain:

- A scanner extension is a self-contained Python package (`src/SCANNER_extension/`) that wraps a
  CLI-based vulnerability scanner and feeds its results into ODG as `VulnerabilityFinding` records.
- It integrates via the standard backlog/orchestrator pattern: the artefact enumerator creates
  backlog items, the extension processes them by calling the scanner CLI, and `scanner_utils`
  converts the CycloneDX output into findings stored in the delivery-db.
- The end result includes: `scanner.py` (subprocess wrapper), `__main__.py` (entry point), a Helm
  chart, and wiring in `model.py`, `extensions_cfg.py`, and `artefact_enumerator.py`.

Then ask the user for:
1. Scanner name (e.g. "trivy", "grype") — used for package names, class names, and the datasource key
2. Scanner CLI install snippet for the Dockerfile (or "skip" if not needed yet)
3. Which scanning modes to support: binary, sbom, sbom_with_binary_fallback (default: all three)
4. Which OCM artefact types and access types to support (see list below)

### OCM artefact & access types supported by ODG:

Excerpt:

- artefact_kinds: `odg.model.ArtefactKind.RESOURCE`
- access_types: `ocm.AccessType.LOCAL_BLOB`, `.OCI_BLOB`, `.OCI_REGISTRY`, `.S3`, `.S3_V2`
- artefact_types: `ocm.ArtefactType.BLOB`, `DIRECTORY_TREE`, `EXECUTABLE`, `OCI_ARTEFACT`, `OCI_IMAGE`, `SBOM`

See `src/odg/model.py` for a full list.

## Implementation

Then implement the following, replacing SCANNER with the scanner name and SCANNER_NAME with its
camelCase Services enum value:

### 0. Deep research on Scanner CLI commands

Do not assume how the commands are structured and how they work, research before you start implementing:

- How to scan different artefact types?
- How to output vulnerability findings in CycloneDX format?
Ask clarifying questions as needed


### 1. src/odg/model.py

Add `SCANNER = 'scanner'` to the `Datasource` StrEnum (keep alphabetical order), and add
`Datasource.SCANNER: (Datatype.VULNERABILITY_FINDING,)` to `Datasource.datatypes()`

### 2. src/odg/extensions_cfg.py

- Add `SCANNER_NAME = 'scannerName'` to `Services` StrEnum (keep alphabetical order)
- Add `ScannerMapping(Mapping)` dataclass — inherits `prefix: str`; no extra fields unless needed
- Add `ScannerConfig(BacklogItemMixins)`, matching the types supported by the scanner. Please study the existing configs (e.g. BDBA, Trivy, Grype) and adjust to your scanner as needed.
- Add `scanner: ScannerConfig | None = None` to `ExtensionsConfiguration`
- Add `('scanner_name', self.scanner)` to the `vuln_scanners` list inside `__post_init__`

### 3. .devcontainer/Dockerfile

Add the CLI install snippet. For scanners distributed as a Docker image use a multi-stage COPY:

```dockerfile
COPY --from=vendor/scanner:latest /usr/local/bin/scanner /usr/local/bin/scanner
```

### 4. src/scanner_extension/__init__.py

Empty file.

### 5. src/scanner_extension/scanner.py + unit tests

1. Inherit from `scanner_utils.orchestrator.Scanner` (`src/scanner_utils/orchestrator.py`). Do not implement any functions yet.
2. Then write `src/test/test_SCANNER_extension.py` with tests calling the scanner CLI with real data (failing tests first, no mocking yet)
2. Implement `scanner.py` until all real-mode tests pass
3. Trim one return value per subcommand to empty `components` + one CVE id, store in `_MOCK_STDOUT`.
4. Add `SCANNER_USE_MOCK=true` (default): autouse fixture patches `_run_SCANNER` and any filesystem operations in `scanner.py`. Verify both modes pass.

See `src/trivy_extension/scanner.py` and `src/test/test_trivy_extension.py` for final implementations.


### 6. src/scanner_extension/__main__.py

Copy from `src/trivy_extension/__main__.py` and adjust for your scanner extension. This file is the entrypoint to your extension. It only wires config to call `run_scan` — no orchestration logic


### 7. src/artefact_enumerator.py

In `_process_compliance_snapshot_of_artefact()`, add a block after the last scanner block. Study the setup of prior scanners (e.g. BDBA, Trivy or Grype) and adjust to your implementation.

### 8. .vscode/launch.json

Add the new extension to the `options` list of the `extension` input (keep alphabetical order).

### 9. extension-definitions.yaml

Add an entry to `extension-definitions.yaml` (root of the repo) for the new scanner, following the pattern of existing scanner entries (e.g. `bdba`). Use `delivery-service` and `delivery-db` as dependencies, set `SCANNER.enabled: true` and `SCANNER.target_namespace: ${target_namespace}`, and add `SCANNER.deployment.annotations."resources.gardener.cloud/preserve-replicas": '"true"'`.

### 10. Helm chart

Four touch-points in `charts/extensions/`:

**charts/extensions/charts/SCANNER/Chart.yaml**
```yaml
apiVersion: v2
name: SCANNER
version: 0.1.0
```

**charts/extensions/charts/SCANNER/templates/SCANNER.yaml**
Copy from `charts/extensions/charts/trivy/templates/trivy.yaml` and `charts/extensions/charts/trivy/templates/trivy.yaml` the relevant parts for your scanner extension and substitute:
- `$podName` → `"SCANNER"`
- Both `delivery-gear.gardener.cloud/service:` label values → `SCANNER`
- `command` → `python3 -m SCANNER_extension`
- If the scanner needs no external credentials: remove the scanner-specific secret volume (keep aws, github, github-app, kubernetes, oci-registry as optional)
- NetworkPolicy name → `allow-egress-from-SCANNER`
- `terminationGracePeriodSeconds`: `1800` for slow scanners (binary pulls), `300` for SBOM-only

**charts/extensions/Chart.yaml** — add dependency (alphabetical):
```yaml
- name: SCANNER
  repository: file://charts/SCANNER
  condition: SCANNER.enabled
```

**charts/extensions/values.yaml** — append your values

If finished, lint the Helm chart with `helm lint`

If the CVE scanner (e.g. Trivy) downloads their CVE database on startup, ensure
the signatures during Pods restarts can be cached

## Key rules

- Emit `odg.model.VulnerabilityFinding` — NOT `BDBAVulnerabilityFinding`
- `scanner.py` only runs subprocesses or API/lib calls — all finding logic is in `scanner_utils`
- `__main__.py` only wires config and calls `run_scan` — no orchestration logic
- Do NOT emit RESCORING or SCANNER_WRITEBACK records
- Always pass `datasource` explicitly — never use `Datatype.datasource()`
- Never override `scan_ocm_resource` — it is the base class dispatch method
- Blob fetching (OCI, LOCAL_BLOB, S3) is handled by `ocm_util.iter_blob_descriptors` inside `scan_ocm_resource`; hooks only receive an already-fetched path or blob descriptor
- After creating all files, run `uv run python -m pytest src/test/ -q` and fix any failures
