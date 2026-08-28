# odg-core

These are Python 3.14 backend services of *Open Delivery Gear*. ODG integrates compliance into the software
lifecycle through automated scanning, tracking, and reporting of security findings, vulnerabilities,
and compliance issues for your [OCM](https://ocm.software) components.

ODG is built as a collection of independent extensions, each running as its own process and implementing a
specific capability (scanning, reporting, replication, etc.); extensions share common infrastructure from `src/`
(domain model, DB access, secret handling,  etc.); they are deployed and scaled via their own Helm sub-chart.
  
## Project structure

**Configuration**
- `src/features/features_cfg.yaml` — app config (special components, sprints, etc.)
- `src/odg/extensions_cfg.yaml` — extension-specific config 
- `src/odg/ocm_repo_mappings.yaml` — config to map OCM components to OCI registries
- `src/odg/profiles.yaml` — ODG profiles
- `src/secrets/` — secret YAML templates (one type per subdirectory)
- `extension-definitions.yaml` — extension definitions

**Extensions** in `src/` (each maps to a Helm sub-chart under `charts/extensions/charts/<name>/`):
- `access_manager_extension.py` — access manager
- `artefact_enumerator.py` — artefact enumeration
- `backlog_controller.py` — backlog controller
- `bdba_extension/` — BDBA binary analysis
- `cache_manager.py` — cache manager
- `codeql.py` — CodeQL integration
- `crypto_extension/` — cryptography/CBOM
- `delivery_db_backup.py` — delivery DB backup
- `ghas.py` — GitHub Advanced Security
- `issue_replicator/` — GitHub issue replication
- `malware/` + `freshclam/` — ClamAV malware scanning + virus-definition updater
- `odg_operator/` — Kubernetes operator
- `osid_extension/` — OS-ID detection
- `responsibles_extension/` — responsible-user lookup
- `sast.py` — SAST scanning
- `sbom_generator.py` — SBOM generation
- `sla_violation_profiler.py` — SLA violation profiler
- `trivy_extension/` — Trivy vulnerability scanning

**Shared libraries** in `src/`:
- `bdba/`, `bdba_utils/` — BDBA client and utilities
- `blobstore/` — blob storage abstraction
- `cli/` — CLI commands
- `delivery/` — delivery service client
- `deliverydb/` — delivery DB ORM and query helpers
- `deliverydb_cache/` — delivery DB caching layer
- `features/` — feature flags and license data
- `k8s/` — Kubernetes interaction utilities
- `middleware/` — ASGI middleware (auth, CORS, DB session, Prometheus)
- `odg/` — core domain model, config, and findings definitions
- `odg_client/` — ODG API client library
- `osinfo/` — OS/distro info utilities
- `rescore/` — rescoring logic
- `responsibles/` — responsible-user lookup logic
- `scanner_utils/` — shared scanner infrastructure (orchestrator, CycloneDX output, findings, rescoring)
- `schema/` — JSON schema definitions
- `secret_mgmt/` — secret/credential management per backend
- `sprints/` — sprint/milestone tracking
- `swagger/` — OpenAPI spec

**Helm charts** (`charts/`):
- `bootstrapping/` — bootstraps config and secrets into a cluster
- `delivery-service/` — main delivery service (Deployment, HPA, RBAC, CRD)
- `extensions/` — umbrella chart; sub-chart per extension under `charts/extensions/charts/<name>/`

**Client packages** (`packages/`, uv workspace members, built separately):
- `bdba-client/` — `bdba-client` wheel (sources `src/bdba*`; version in `BDBA_CLIENT_VERSION`)
- `odg-client/` — `odg-client` wheel (sources `src/delivery*`, `src/odg_client*`; version in `ODG_CLIENT_VERSION`)

**Tests**: `src/test/` — pytest unit tests

## Conventions

* Follow ruff and bandit rules from `pyproject.toml`
* Always end files with a new line
* Set reasonable type hints (avoid `Any` or `object`)
* Use expressive variable names (`item` over `i`)
* In logs:
    * Prefer `{param=}` over `param={param}`
    * Many classes implement `__str__`
* Prefer `is` over `==` when comparing enum values
* Be conscise, specific and value dense

## After you finished

* Run tests with `make test`
* Lint/format with `make lint && make format` after the feature is ready
* Update documentation as needed:
  * Check for breaking changes in `README.md`
  * For extension specific configuration: `charts/bootstrapping/values.documentation.yaml`
  * For API changes: `src/swagger/swagger.yaml`

## Boundaries

* Always run Python commands with `uv run`
* Never run `make setup` or `make run`, ask user if needed
* Never create commits or PRs yourself, let the user sign & signoff

## Hints

* oci/ocm libs: https://github.com/gardener/cc-utils
* OCM spec: https://github.com/open-component-model/ocm-spec/tree/main/doc
