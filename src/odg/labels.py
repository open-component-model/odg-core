import dataclasses
import enum
import functools
import inspect
import sys

import dacite

import ocm
import ocm.iter

import odg.cvss


class ScanPolicy(enum.Enum):
    SCAN = 'scan'
    SKIP = 'skip'


@dataclasses.dataclass(frozen=True)
class LabelValue:
    pass


@dataclasses.dataclass(frozen=True)
class Label:
    name: str
    value: LabelValue


@dataclasses.dataclass(frozen=True)
class BinaryScanPolicy(LabelValue):
    policy: ScanPolicy
    comment: str | None = None


@dataclasses.dataclass(frozen=True)
class BinaryScanPolicyLabel(Label):
    name = 'odg.ocm.software/binary-scan-policy'
    value: BinaryScanPolicy


@dataclasses.dataclass(frozen=True)
class SourceScanPolicy(LabelValue):
    policy: ScanPolicy
    comment: str | None = None


@dataclasses.dataclass(frozen=True)
class SourceScanPolicyLabel(Label):
    name = 'odg.ocm.software/source-scan-policy'
    value: SourceScanPolicy


@dataclasses.dataclass(frozen=True)
class PurposeLabel(Label):
    name = 'odg.ocm.software/purposes'
    value: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class PackageVersionHint:
    name: str
    version: str


@dataclasses.dataclass(frozen=True)
class PackageVersionHintLabel(Label):
    name = 'cloud.gardener.cnudie/dso/scanning-hints/package-versions'
    value: tuple[PackageVersionHint, ...]


@dataclasses.dataclass(frozen=True)
class RiskProfileLabel(Label):
    name = 'security.ocm.software/risk-profile'
    value: odg.cvss.CveCategorisation


@functools.cache
def _label_to_type() -> dict[str, Label]:
    own_module = sys.modules[__name__]
    types = tuple(
        t
        for entry in inspect.getmembers(own_module, inspect.isclass)
        if (t := entry[1]) != Label and issubclass(t, Label)
    )

    label_names_to_types = {}
    for t in types:
        label_names_to_types[t.name] = t

    return label_names_to_types


_LABEL_NAME_ALIASES = {
    'cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1': BinaryScanPolicyLabel.name,
    'cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1': SourceScanPolicyLabel.name,
    'gardener.cloud/cve-categorisation': RiskProfileLabel.name,
    'gardener.cloud/purposes': PurposeLabel.name,
}


@functools.cache
def get_label_names_with_aliases(label_type: type[Label]) -> list[str]:
    return [label_type.name] + [
        k for k, v in _LABEL_NAME_ALIASES.items()
        if v == label_type.name
    ]


def deserialise_label(
    label: ocm.Label | dict,
):
    if isinstance(label, ocm.Label):
        label = {
            'name': label.name,
            'value': label.value,
        }

    name = _LABEL_NAME_ALIASES.get(label['name'], label['name'])

    if not (t := _label_to_type().get(name)):
        raise ValueError(f"unknown {label['name']=}")

    return dacite.from_dict(
        data_class=t,
        data=label,
        config=dacite.Config(
            cast=[tuple, enum.Enum],
        ),
    )


def find_source_scan_policy(
    snode: ocm.iter.SourceNode,
) -> ScanPolicy | None:
    for name in get_label_names_with_aliases(SourceScanPolicyLabel):
        if label := snode.source.find_label(name=name):
            return deserialise_label(label).value.policy

    for name in get_label_names_with_aliases(SourceScanPolicyLabel):
        if label := snode.component.find_label(name=name):
            return deserialise_label(label).value.policy

    return None
