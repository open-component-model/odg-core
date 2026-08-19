# Open Delivery Gear - Core

This repository is the home of the core API and feature extensions for the [Open Delivery Gear](https://github.com/open-component-model/open-delivery-gear).

[![REUSE status](https://api.reuse.software/badge/github.com/open-component-model/odg-core)](https://api.reuse.software/info/github.com/open-component-model/odg-core)
![tests](https://github.com/open-component-model/odg-core/actions/workflows/non-release.yaml/badge.svg)
![release](https://github.com/open-component-model/odg-core/actions/workflows/release.yaml/badge.svg)

## Index

- [Technology](#technology)
- [Getting Started](#getting-started)
  - [Standalone](#standalone)
  - [Kubernetes in Docker](#kubernetes-in-docker)
- [Documentation](#documentation)
- [Packages](#packages)

## Technology

The core API implements a Python HTTP web server, intended for deployment into a Kubernetes cluster. It features compliance-related automation for software built with the [Open Component Model](https://ocm.software/).

## Getting Started

There are multiple ways to run ODG-Core locally.

### Standalone

The ODG-Core Python HTTP web server can be started locally as a standalone application. It is loosely coupled to the database and Kubernetes-specific components, therefore this option is considered best if you intend to run web server-only features (e.g. adding new endpoints).

#### Dependencies and Setup

First, you need to prepare your local environment. Install `uv` (e.g. `brew install uv`), then run:

```shell
make setup
```

This creates a project-local `.venv` with all dependencies pinned from `uv.lock`. Afterwards you can either prefix commands with `uv run` (e.g. `uv run pytest`) or activate the venv manually.

Common Makefile targets:

| Target | Description |
| --- | --- |
| `make setup` | Create/update `.venv` from lock file |
| `make run-db` | Start a local PostgreSQL instance |
| `make run` | Start the development server |
| `make test` | Run the test suite |
| `make lint` | Run ruff and bandit |
| `make format` | Check code formatting |
| `make build-core` | Build the `odg-core-libs` wheel |
| `make build-clients` | Build `bdba-client` and `odg-client` wheels |
| `make build-docker-local` | Build the OCI image for your local architecture |
| `make build-docker` | Build the OCI image for all supported architectures |
| `make clean` | Remove build artifacts |

#### Running the Web Server

The Makefile features a convenient command to run the ODG-Core web server in a lightweight fashion. This naturally has limitations, as most features will be turned off.
If you want to run specific features, please review the Makefile and build your custom `run` command.

```shell
make run
```

### Kubernetes in Docker

To run the ODG-Core web server alongside dependencies and feature extensions, you need to deploy it to a Kubernetes environment.
You can use Kubernetes-in-Docker (KinD) to deploy such a setup locally.

Please refer to [this guide](https://open-component-model.github.io/open-delivery-gear/contents/how-to/01-local-setup.html) to deploy ODG to KinD.

### Dev Container

You can also develop ODG in a [Dev Container](https://code.visualstudio.com/docs/devcontainers/containers). Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) and choose **Reopen in Container** in VS Code.

The Dev Container provides:

* Run & debug:
  * To run the core service, run `Debug: core service`
  * To run an extension, run `Debug: extension` and select the extension
* Pytest integration
* PostgreSQL browser (password: `MyPassword`, see `.devcontainer/compose.yml`)
* Auto-format & lint on save

To work with a KinD cluster:

1. Create the KinD cluster on the host: `kind create cluster --config .devcontainer/kind-config.yml`, which includes `host.docker.internal` as SAN
1. Flatten your kubeconfig into `~/.kube/config`: `kubectl config view --flatten > ~/.kube/config`
1. Open the Dev Container (**Reopen in Container** in VS Code)
1. Open a terminal session. The kubeconfig is refreshed on every shell startup, with `127.0.0.1` replaced by `host.docker.internal`
1. Copy the extensions config: `cp extensions_cfg.yaml extensions_cfg.local.yaml`
1. Adjust the local [configuration and secrets](https://open-component-model.github.io/open-delivery-gear/contents/how-to/00-hybrid-dev-setup.html#configuration-and-secrets) to your needs

To clean up the KinD cluster: `kind delete clusters odg-devcontainer-cluster`

## Documentation

The documentation is hosted [here](https://open-component-model.github.io/open-delivery-gear/index.html).

### Quicklinks

- [Architecture Overview](https://open-component-model.github.io/open-delivery-gear/contents/concepts/00-odg-architecture.html)
- [Onboarding Journey](https://open-component-model.github.io/open-delivery-gear/contents/getting-started/00-introduction.html)
- [Reference Documentation](https://open-component-model.github.io/open-delivery-gear/index.html#references)

### Open-API Specification

Additionally, each ODG-Core instance hosts an Open-API specification.
It is available at:
`https://<odg-core>/api/v1/doc/`

You can also checkout the documentation hosted by the public demo instance, but please be aware that the running version might differ from your installation.

-> [Public ODG Demo Open-API](https://delivery-service.demo.ci.gardener.cloud/api/v1/doc/)

## Packages

ODG-Core publishes multiple software artefacts.
This list provides an overview.

| Name | Type | Description | Location |
| --- | --- | --- | --- |
| `odg-core-libs` | Python Package | Core APIs and functionalities. Contains the ODG web server. | [PyPi](https://pypi.org/project/odg-core-libs/) |
| `odg-client` | Python Package | Python HTTP client library to interact with the ODG-Core API | [PyPi](https://pypi.org/project/odg-client/) |
| `bdba-client` | Python Package | Python HTTP client library to interact with BlackDuck Binary Analysis | [PyPi](https://pypi.org/project/bdba-client/) |
| `odg-core` | OCI Image | Filesystem to run ODG-Core and ODG extensions in cloud environments | [GCP](https://europe-docker.pkg.dev/gardener-project/releases/odg/core) |
| `odg-core` | OCM Component | Software component referencing all delivery artefacts and metadata | [OCM Repo](https://europe-docker.pkg.dev/gardener-project/releases/component-descriptors/ocm.software/open-delivery-gear/core) |

---

<p align="center"><img alt="Bundesministerium für Wirtschaft und Energie (BMWE)-EU funding logo" src="https://apeirora.eu/assets/img/BMWK-EU.png" width="400"/></p>
