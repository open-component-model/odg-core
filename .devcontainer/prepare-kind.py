#!/usr/bin/env python3
"""
Prepare the kind devcontainer cluster:
  1. Apply ODG custom CRDs from charts/delivery-service/crds and charts/extensions/crds
  2. Write src/secrets/kubernetes/devcontainers-cluster.yaml from the kubeconfig for
     cluster "kind-odg-devcontainer-cluster" found in ~/.kube

All kubectl operations are scoped to "kind-odg-devcontainer-cluster" without
permanently changing the active context.
"""

import pathlib
import subprocess
import sys

import yaml

CLUSTER_NAME = 'kind-odg-devcontainer-cluster'
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CRD_DIRS = [
    REPO_ROOT / 'charts' / 'delivery-service' / 'crds',
    REPO_ROOT / 'charts' / 'extensions' / 'crds',
]
SECRET_PATH = REPO_ROOT / 'src' / 'secrets' / 'kubernetes' / 'devcontainers-cluster.yaml'
KUBE_DIR = pathlib.Path.home() / '.kube'


def load_kubeconfig() -> dict:
    config_path = KUBE_DIR / 'config'
    if not config_path.exists():
        sys.exit(f'kubeconfig not found at {config_path}')
    with open(config_path) as f:
        return yaml.safe_load(f)


def find_cluster_entry(kubeconfig: dict, cluster_name: str) -> dict:
    for entry in kubeconfig.get('clusters', []):
        if entry['name'] == cluster_name:
            return entry
    available = [e['name'] for e in kubeconfig.get('clusters', [])]
    sys.exit(
        f'Cluster "{cluster_name}" not found in kubeconfig.\nAvailable clusters: {available}',
    )


def find_context_entry(kubeconfig: dict, cluster_name: str) -> dict:
    for entry in kubeconfig.get('contexts', []):
        if entry['context']['cluster'] == cluster_name:
            return entry
    sys.exit(f'No context found for cluster "{cluster_name}"')


def find_user_entry(kubeconfig: dict, user_name: str) -> dict:
    for entry in kubeconfig.get('users', []):
        if entry['name'] == user_name:
            return entry
    sys.exit(f'User "{user_name}" not found in kubeconfig')


def apply_crds(cluster_name: str) -> None:
    crd_files = []
    for crd_dir in CRD_DIRS:
        if not crd_dir.is_dir():
            print(f'Warning: CRD directory not found: {crd_dir}', file=sys.stderr)
            continue
        crd_files.extend(sorted(crd_dir.glob('*.yaml')))

    for crd_file in crd_files:
        print(f'Applying CRD: {crd_file.relative_to(REPO_ROOT)}')
        subprocess.run(  # nosec B607 -- kubectl is a well-known tool resolved via PATH
            ['kubectl', '--context', cluster_name, 'apply', '-f', str(crd_file)],
            check=True,
        )


def write_secret(kubeconfig: dict, cluster_name: str) -> None:
    cluster_entry = find_cluster_entry(kubeconfig, cluster_name)
    context_entry = find_context_entry(kubeconfig, cluster_name)
    user_name = context_entry['context']['user']
    user_entry = find_user_entry(kubeconfig, user_name)

    context_name = context_entry['name']
    minimal_kubeconfig = {
        'apiVersion': 'v1',
        'kind': 'Config',
        'current-context': context_name,
        'clusters': [cluster_entry],
        'contexts': [context_entry],
        'users': [user_entry],
    }

    secret = {'kubeconfig': minimal_kubeconfig}
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SECRET_PATH, 'w') as f:
        content = yaml.dump(secret, default_flow_style=False, allow_unicode=True)
        f.write(content.replace('127.0.0.1', 'host.docker.internal'))
    SECRET_PATH.chmod(0o600)
    print(f'Written: {SECRET_PATH.relative_to(REPO_ROOT)}')


def main() -> None:
    kubeconfig = load_kubeconfig()
    apply_crds(CLUSTER_NAME)
    write_secret(kubeconfig, CLUSTER_NAME)
    print('Done.')


if __name__ == '__main__':
    main()
