import dataclasses
import enum
import hashlib

import ocm


class EncodingFormat(enum.StrEnum):
    JSON = 'json'
    YAML = 'yaml'


class CacheValueType(enum.StrEnum):
    COMPONENT_DESCRIPTOR = 'component-descriptor'
    PYTHON_FUNCTION = 'python-function'
    HTTP_ROUTE = 'http-route'


@dataclasses.dataclass
class CacheDescriptorBase:
    type: CacheValueType
    encoding_format: EncodingFormat

    @property
    def key(self) -> str:
        raise NotImplementedError('subclasses must overwrite')

    @property
    def id(self) -> str:
        # not using byte digest here since sqlalchemy only supports `LargeBinary` datatype for
        # storing plain bytes on postgresql, hence using string with fixed length is more efficient
        return hashlib.blake2s(
            self.key.encode('utf-8'),
            digest_size=16,
            usedforsecurity=False,
        ).hexdigest()


@dataclasses.dataclass(kw_only=True)
class CachedComponentDescriptor(CacheDescriptorBase):
    type: CacheValueType = CacheValueType.COMPONENT_DESCRIPTOR
    component_name: str
    component_version: str
    ocm_repository: ocm.OciOcmRepository

    @property
    def key(self) -> str:
        return (
            f'{self.type}|{self.encoding_format}|'
            f'{self.component_name}|{self.component_version}|{self.ocm_repository.oci_ref}'
        )


@dataclasses.dataclass(kw_only=True)
class CachedPythonFunction(CacheDescriptorBase):
    type: CacheValueType = CacheValueType.PYTHON_FUNCTION
    function_name: str
    args: str
    kwargs: str

    @property
    def key(self) -> str:
        return f'{self.type}|{self.encoding_format}|{self.function_name}|{self.args}|{self.kwargs}'


@dataclasses.dataclass(kw_only=True)
class CachedHTTPRoute(CacheDescriptorBase):
    type: CacheValueType = CacheValueType.HTTP_ROUTE
    route: str
    params: str | None = None
    body: str | None = None

    @property
    def key(self) -> str:
        return f'{self.type}|{self.encoding_format}|{self.route}|{self.params}|{self.body}'
