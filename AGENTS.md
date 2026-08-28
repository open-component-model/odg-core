# odg-core

These are Python 3.14 backend services of *Open Delivery Gear*. ODG integrates compliance into the software
lifecycle through automated scanning, tracking, and reporting of security findings, vulnerabilities,
and compliance issues for your [OCM](ocm.software) components.

## Dev environment tips

* Multi-package repo using `uv` and `setuptools`
* Use `uv ...` to run Python commands
* Run tests with `make test`
* Lint/format with `make lint && make format`
* Project structure:
    * `src/` app source code
    * `src/tests/` tests
    * `packages` built `bdba-client` & `odg-client` packages from `src`
    * `charts` Helm charts for deployment

## Setup commands

* Initial setup: `make setup`
* Run tests: `make test`
* Lint/format: `make lint && make format`

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

## Boundaries

* Never run `make setup`, user already ran it
* Never create commits yourself, let the user sign & signoff

## Hints

* oci/ocm libs: https://github.com/gardener/cc-utils
* OCM spec: https://github.com/open-component-model/ocm-spec/tree/main/doc
