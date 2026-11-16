import dataclasses
import datetime
import enum
import hashlib
import http
import os
import time

import dacite
import dateutil.parser
import kubernetes.client.rest
import structlog

import k8s.model
import k8s.util
import odg.extensions_cfg
import odg.model
import util

logger = structlog.get_logger(__name__)

LABEL_CLAIMED = f'{k8s.model.BacklogItemCrd.DOMAIN}/claimed'


class BacklogItemPhase(enum.StrEnum):
    FAILED = 'Failed'
    PENDING = 'Pending'
    PROCESSING = 'Processing'


class BacklogPriorities(enum.IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 4
    CRITICAL = 8


@dataclasses.dataclass
class BacklogItem:
    timestamp: datetime.datetime
    artefact: odg.model.ComponentArtefactId
    priority: BacklogPriorities

    def as_dict(self) -> dict:
        return util.dict_serialisation(self)

    @staticmethod
    def from_dict(backlog_item: dict) -> 'BacklogItem':
        type_hooks = {
            datetime.datetime: lambda ts: dateutil.parser.isoparse(ts) if ts else None,
        }

        return dacite.from_dict(
            data_class=BacklogItem,
            data=backlog_item,
            config=dacite.Config(
                type_hooks=type_hooks,
                cast=[
                    BacklogPriorities,
                    odg.model.ArtefactKind,
                ],
            ),
        )


def create_backlog_item_name(
    service: odg.extensions_cfg.Services,
    artefact: odg.model.ComponentArtefactId,
) -> str:
    artefact_digest = hashlib.blake2s(
        artefact.key.encode('utf-8'),
        digest_size=16,
        usedforsecurity=False,
    ).hexdigest()

    return k8s.util.generate_kubernetes_name(
        name_parts=(service, artefact_digest),
        generate_num_suffix=False,
    )


def create_backlog_crd_body(
    service: str,
    name: str,
    namespace: str,
    backlog_item: BacklogItem,
) -> dict:
    return {
        'apiVersion': k8s.model.BacklogItemCrd.api_version(),
        'kind': k8s.model.BacklogItemCrd.KIND,
        'metadata': {
            'labels': {
                k8s.model.LABEL_SERVICE: service,
            },
            'name': name,
            'namespace': namespace,
        },
        'spec': backlog_item.as_dict(),
        'status': {
            'phase': BacklogItemPhase.PENDING,
            'last_updated': datetime.datetime.now(tz=datetime.timezone.utc).strftime(
                '%Y-%m-%dT%H:%M:%SZ',
            ),
        },
    }


def find_backlog_item(
    service: odg.extensions_cfg.Services,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    artefact: odg.model.ComponentArtefactId,
) -> dict | None:
    name = create_backlog_item_name(
        service=service,
        artefact=artefact,
    )

    try:
        return kubernetes_api.custom_kubernetes_api.get_namespaced_custom_object(
            group=k8s.model.BacklogItemCrd.DOMAIN,
            version=k8s.model.BacklogItemCrd.VERSION,
            plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
            namespace=namespace,
            name=name,
        )
    except kubernetes.client.rest.ApiException as e:
        if e.status == http.HTTPStatus.NOT_FOUND:
            return None
        raise e


def _create_backlog_item(
    service: odg.extensions_cfg.Services,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    artefact: odg.model.ComponentArtefactId,
    priority: BacklogPriorities = BacklogPriorities.LOW,
):
    name = create_backlog_item_name(
        service=service,
        artefact=artefact,
    )

    backlog_item = BacklogItem(
        timestamp=datetime.datetime.now(),
        artefact=artefact,
        priority=priority,
    )

    body = create_backlog_crd_body(
        service=service,
        name=name,
        namespace=namespace,
        backlog_item=backlog_item,
    )

    kubernetes_api.custom_kubernetes_api.create_namespaced_custom_object(
        group=k8s.model.BacklogItemCrd.DOMAIN,
        version=k8s.model.BacklogItemCrd.VERSION,
        plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
        namespace=namespace,
        body=body,
    )


def create_backlog_item(
    service: odg.extensions_cfg.Services,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    artefact: odg.model.ComponentArtefactId,
    priority: BacklogPriorities = BacklogPriorities.LOW,
) -> bool:
    """
    creates a backlog item for the given `artefact` and `priority`. If there is
    already an existing backlog item which is semantically equal, the creation is
    skipped. However, if the priority of the existing backlog item is lower than
    `priority`, the old backlog item will be patched with the new priority.
    Returns `True` if a new backlog item was created, otherwise `False`.
    """
    try:
        _create_backlog_item(
            service=service,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            artefact=artefact,
            priority=priority,
        )
        return True
    except kubernetes.client.rest.ApiException as e:
        if e.status != http.HTTPStatus.CONFLICT:
            raise

    if not (
        backlog_item := find_backlog_item(
            service=service,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            artefact=artefact,
        )
    ):
        raise RuntimeError('create conflict but backlog item could not be reloaded')

    metadata = backlog_item.get('metadata')
    old_priority = backlog_item.get('spec').get('priority')

    if old_priority < priority:
        backlog_item['spec']['priority'] = priority

        kubernetes_api.custom_kubernetes_api.patch_namespaced_custom_object(
            group=k8s.model.BacklogItemCrd.DOMAIN,
            version=k8s.model.BacklogItemCrd.VERSION,
            plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
            namespace=namespace,
            name=metadata.get('name'),
            body=backlog_item,
        )

    return False


def set_backlog_item_status(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    backlog_crd: dict,
    phase: BacklogItemPhase,
    claimed_by: str | None = None,
    claimed_at: datetime.datetime | None = None,
    error: dict | None = None,
    max_retries: int = 3,
    retry_count: int = 0,
) -> dict:
    metadata = backlog_crd.get('metadata')
    name = metadata.get('name')

    status = {
        'phase': phase,
        'claimed_by': claimed_by,
        'claimed_at': claimed_at.strftime('%Y-%m-%dT%H:%M:%SZ') if claimed_at else None,
        'last_updated': datetime.datetime.now(tz=datetime.timezone.utc).strftime(
            '%Y-%m-%dT%H:%M:%SZ',
        ),
        'error': error,
    }
    backlog_crd['status'] = status

    try:
        # use "replace" instead of "patch" here to allow running in a conflict
        # -> "patch" silently ignores conflicts and overrides the resource anyways
        backlog_crd = kubernetes_api.custom_kubernetes_api.replace_namespaced_custom_object(
            group=k8s.model.BacklogItemCrd.DOMAIN,
            version=k8s.model.BacklogItemCrd.VERSION,
            plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
            namespace=namespace,
            name=name,
            body=backlog_crd,
        )
    except kubernetes.client.rest.ApiException as e:
        if e.status != http.HTTPStatus.CONFLICT or retry_count >= max_retries:
            raise e

        retry_interval = (retry_count + 1) * 10
        logger.warning(
            'trying to update backlog item status resulted in a conflict, will retry in '
            f'{retry_interval} sec...',
        )
        time.sleep(retry_interval)
        return set_backlog_item_status(
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            backlog_crd=backlog_crd,
            phase=phase,
            claimed_by=claimed_by,
            claimed_at=claimed_at,
            error=error,
            max_retries=max_retries,
            retry_count=retry_count + 1,
        )

    return backlog_crd


def get_backlog_crd_and_claim(
    service: odg.extensions_cfg.Services,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    shortcut_claim: bool = False,
) -> dict | None:
    labels = {
        k8s.model.LABEL_SERVICE: service,
    }
    label_selector = k8s.util.create_label_selector(labels=labels)
    label_selector += f', {LABEL_CLAIMED}!=True'

    backlog_crds = kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object(
        group=k8s.model.BacklogItemCrd.DOMAIN,
        version=k8s.model.BacklogItemCrd.VERSION,
        plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
        namespace=namespace,
        label_selector=label_selector,
    ).get('items')

    if not backlog_crds:
        return None

    backlog_crds.sort(
        key=lambda backlog_crd: (
            -BacklogPriorities(backlog_crd.get('spec').get('priority')),  # negate for high to low
            backlog_crd.get('spec').get('timestamp'),
        ),
    )

    backlog_crd = backlog_crds[0]

    if shortcut_claim:
        return backlog_crd

    metadata = backlog_crd.get('metadata')

    labels = metadata.get('labels')

    labels[LABEL_CLAIMED] = 'True'
    metadata['labels'] = labels

    return set_backlog_item_status(
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        backlog_crd=backlog_crd,
        phase=BacklogItemPhase.PROCESSING,
        claimed_by=os.environ.get('HOSTNAME', 'local'),
        claimed_at=datetime.datetime.now(tz=datetime.timezone.utc),
    )


def remove_claim(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    backlog_crd: dict,
) -> dict:
    metadata = backlog_crd.get('metadata')
    name = metadata.get('name')

    labels = metadata.get('labels')
    labels[LABEL_CLAIMED] = 'False'
    metadata['labels'] = labels

    logger.info(f'attempting to remove claim from backlog item {name} in {namespace=}')

    backlog_crd = set_backlog_item_status(
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        backlog_crd=backlog_crd,
        phase=BacklogItemPhase.PENDING,
    )

    logger.info(f'removed claim from backlog item {name} in {namespace=}')

    return backlog_crd


def update_backlog_crd(
    name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    backlog_item: BacklogItem,
):
    body = {
        'spec': backlog_item.as_dict(),
    }

    try:
        kubernetes_api.custom_kubernetes_api.patch_namespaced_custom_object(
            group=k8s.model.BacklogItemCrd.DOMAIN,
            version=k8s.model.BacklogItemCrd.VERSION,
            plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
            namespace=namespace,
            name=name,
            body=body,
        )
    except kubernetes.client.rest.ApiException as e:
        # if the http status is 404 it is fine because then it was already processed
        # and must not be updated anymore
        if e.status != http.HTTPStatus.NOT_FOUND:
            raise e
