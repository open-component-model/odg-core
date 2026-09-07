import dataclasses
import enum
import re

import util


RoleName = str


class OAuthCfgTypes(enum.StrEnum):
    GITHUB = 'github'
    OIDC = 'oidc'


class SubjectType(enum.StrEnum):
    GITHUB_APP = 'github-app'
    GITHUB_USER = 'github-user'
    GITHUB_ORG = 'github-org'
    GITHUB_TEAM = 'github-team'
    OIDC_SUB = 'oidc-sub'


@dataclasses.dataclass
class Subject:
    type: SubjectType
    name: str

    def matches(self, name: str) -> bool:
        return bool(re.fullmatch(self.name, name))


@dataclasses.dataclass
class RoleBinding:
    subjects: list[Subject]
    roles: list[RoleName]


@dataclasses.dataclass
class OAuthCfg:
    name: str
    type: OAuthCfgTypes
    api_url: str
    client_id: str
    client_secret: str
    role_bindings: list[RoleBinding] = dataclasses.field(default_factory=list)

    @property
    def normalised_domain(self) -> str:
        return util.normalise_url_to_second_and_tld(self.api_url)

    @property
    def oauth_url(self) -> str:
        return f'https://{self.normalised_domain}/login/oauth/authorize'

    @property
    def token_url(self) -> str:
        return f'https://{self.normalised_domain}/login/oauth/access_token'


@dataclasses.dataclass
class OidcCfg:
    name: str
    issuer: str
    audiences: list[str]
    role_bindings: list[RoleBinding] = dataclasses.field(default_factory=list)

    @property
    def oidc_cfg_url(self) -> str:
        return f'{self.issuer}/.well-known/openid-configuration'
