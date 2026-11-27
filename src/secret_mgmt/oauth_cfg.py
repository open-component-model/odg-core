import dataclasses
import enum
import re

import util

RoleName = str


class OAuthCfgTypes(enum.StrEnum):
    GITHUB = 'github'
    OAUTH = 'oauth'
    OIDC = 'oidc'


class SubjectType(enum.StrEnum):
    GITHUB_APP = 'github-app'
    GITHUB_USER = 'github-user'
    GITHUB_ORG = 'github-org'
    GITHUB_TEAM = 'github-team'
    OAUTH_GROUP = 'oauth-group'
    OAUTH_SUB = 'oauth-sub'
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
    api_url: str
    client_id: str
    client_secret: str = dataclasses.field(repr=False)
    role_bindings: list[RoleBinding] = dataclasses.field(default_factory=list)
    well_known_url: str | None = None
    username_claim: str = 'sub'
    groups_claim: str = 'groups'
    scope: str = 'openid'
    type: OAuthCfgTypes = OAuthCfgTypes.OAUTH

    def __post_init__(self):
        if not self.well_known_url:
            self.well_known_url = util.urljoin(self.api_url, '.well-known/openid-configuration')

    @property
    def normalised_domain(self) -> str:
        return util.normalise_url_to_second_and_tld(self.api_url)

    @property
    def authorization_url(self) -> str | None:
        """
        Authorization endpoint — None for non-GitHub types (fetch from well_known_url instead).
        """
        if self.type is OAuthCfgTypes.GITHUB:
            return f'https://{self.normalised_domain}/login/oauth/authorize'
        return None

    @property
    def token_url(self) -> str | None:
        """
        Token endpoint — None for non-GitHub types (fetch from well_known_url instead).
        """
        if self.type is OAuthCfgTypes.GITHUB:
            return f'https://{self.normalised_domain}/login/oauth/access_token'
        return None

    @property
    def userinfo_url(self) -> str | None:
        """
        Userinfo endpoint — None for non-GitHub types (fetch from well_known_url instead).
        """
        if self.type is OAuthCfgTypes.GITHUB:
            return util.urljoin(self.api_url, 'user')
        return None


@dataclasses.dataclass
class OidcCfg:
    name: str
    issuer: str
    audiences: list[str]
    role_bindings: list[RoleBinding] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        if not self.issuer.startswith('https://'):
            raise ValueError(f'OidcCfg issuer must use HTTPS, got: {self.issuer!r}')

    @property
    def oidc_cfg_url(self) -> str:
        return f'{self.issuer}/.well-known/openid-configuration'
