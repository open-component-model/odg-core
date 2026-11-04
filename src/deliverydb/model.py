import dataclasses
import enum
import hashlib

import dacite
import sqlalchemy as sa
import sqlalchemy.dialects.postgresql as sap
import sqlalchemy.orm
import sqlalchemy.orm.decl_api

import secret_mgmt.oauth_cfg

Base: sqlalchemy.orm.decl_api.DeclarativeMeta = sqlalchemy.orm.declarative_base()

uuid = str
unix_epoch = int

_FINDING_GROUP_KEY_EXPR = (
    'md5(CASE'
    # finding rows — key fields are stored flat in data
    " WHEN type = 'finding/vulnerability' THEN"
    "  coalesce(data->>'cve','None')||'|'||coalesce(data->>'package_name','None')"
    " WHEN type = 'finding/license' THEN"
    "  coalesce(data->'license'->>'name','None')||'|'||coalesce(data->>'package_name','None')"
    " WHEN type = 'finding/ip' THEN"
    "  coalesce(data->>'package_name','None')"
    " WHEN type = 'finding/sast' THEN"
    "  coalesce(data->>'sast_status','None')||'|'||coalesce(data->>'sub_type','None')"
    " WHEN type = 'finding/codeql' THEN"
    "  coalesce(data->>'codeql_status','None')||'|'||coalesce(data->>'repo_url','None')"
    "  ||'|'||coalesce(data->>'language','None')"
    " WHEN type = 'finding/osid' THEN"
    "  coalesce(data->'osid'->>'ID','None')"
    " WHEN type = 'finding/malware' THEN"
    "  coalesce(data->'finding'->>'content_digest','None')"
    "  ||'|'||coalesce(data->'finding'->>'filename','None')"
    "  ||'|'||coalesce(data->'finding'->>'malware','None')"
    " WHEN type = 'finding/diki' THEN"
    "  coalesce(data->>'provider_id','None')||'|'||coalesce(data->>'ruleset_id','None')"
    "  ||'|'||coalesce(data->>'rule_id','None')"
    " WHEN type = 'finding/ghas' THEN"
    "  coalesce(data->>'html_url','None')"
    " WHEN type IN ('finding/falco','finding/kyverno') THEN"
    "  coalesce(data->'finding'->>'group_hash','None')"
    # rescoring rows — key fields are nested under data->'finding' (CustomRescoring.finding)
    " WHEN type = 'rescorings' AND referenced_type = 'finding/vulnerability' THEN"
    "  coalesce(data->'finding'->>'cve','None')"
    "  ||'|'||coalesce(data->'finding'->>'package_name','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/license' THEN"
    "  coalesce(data->'finding'->'license'->>'name','None')"
    "  ||'|'||coalesce(data->'finding'->>'package_name','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/ip' THEN"
    "  coalesce(data->'finding'->>'package_name','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/sast' THEN"
    "  coalesce(data->'finding'->>'sast_status','None')"
    "  ||'|'||coalesce(data->'finding'->>'sub_type','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/codeql' THEN"
    "  coalesce(data->'finding'->>'codeql_status','None')"
    "  ||'|'||coalesce(data->'finding'->>'repo_url','None')"
    "  ||'|'||coalesce(data->'finding'->>'language','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/osid' THEN"
    "  coalesce(data->'finding'->'osid'->>'ID','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/malware' THEN"
    "  coalesce(data->'finding'->>'content_digest','None')"
    "  ||'|'||coalesce(data->'finding'->>'filename','None')"
    "  ||'|'||coalesce(data->'finding'->>'malware','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/diki' THEN"
    "  coalesce(data->'finding'->>'provider_id','None')"
    "  ||'|'||coalesce(data->'finding'->>'ruleset_id','None')"
    "  ||'|'||coalesce(data->'finding'->>'rule_id','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/ghas' THEN"
    "  coalesce(data->'finding'->>'html_url','None')"
    " WHEN type = 'rescorings' AND referenced_type IN ('finding/falco','finding/kyverno') THEN"
    "  coalesce(data->'finding'->>'group_hash','None')"
    ' ELSE NULL END)'
)


class ArtefactMetaData(Base):
    """
    a (meta-)data entry about an artefact described in an OCM-Component-Descriptor.

    Examples of such data are:

    - vulnerability scan results (as e.g. reported from BDBA)
    - malware scan results
    - file system paths
    - operating system identification
    """

    __tablename__ = 'artefact_metadata'

    id = sa.Column(sa.CHAR(length=32), primary_key=True)
    creation_date = sa.Column(
        sa.DateTime(timezone=True),
        server_default=sa.sql.func.now(),
    )

    type = sa.Column(sa.String(length=64))  # e.g. finding/vulnerability, malware, ...

    # component-id
    component_name = sa.Column(sa.String(length=256))
    component_version = sa.Column(sa.String(length=64))

    # artefact-id
    artefact_kind = sa.Column(sa.String(length=32))  # resource | source | runtime

    artefact_name = sa.Column(sa.String(length=128))
    artefact_version = sa.Column(sa.String(length=64))
    artefact_type = sa.Column(sa.String(length=64))

    artefact_extra_id_normalised = sa.Column(sa.String(length=1024))
    artefact_extra_id = sa.Column(sap.JSONB)

    meta = sa.Column(sap.JSONB, default=dict)
    data = sa.Column(sap.JSONB, default=dict)
    finding_group_key = sa.Column(
        sa.String(length=32),
        sa.Computed(_FINDING_GROUP_KEY_EXPR, persisted=True),
    )
    severity = sa.Column(sa.String, sa.Computed("data->>'severity'", persisted=True))
    data_key = sa.Column(sa.CHAR(length=40))
    datasource = sa.Column(sa.String(length=64))  # bdba, clamav, ...

    referenced_type = sa.Column(sa.String(length=64))  # type of finding a rescoring applies to

    discovery_date = sa.Column(sa.Date)
    allowed_processing_time = sa.Column(sa.String(length=16))


sa.Index(
    'ix_artefact_metadata_findings_lookup',
    ArtefactMetaData.component_name,
    ArtefactMetaData.component_version,
    ArtefactMetaData.type,
    ArtefactMetaData.datasource,
)

sa.Index(
    'ix_artefact_metadata_rescorings_lookup',
    ArtefactMetaData.type,
    ArtefactMetaData.referenced_type,
    ArtefactMetaData.component_name,
)

sa.Index(
    'ix_artefact_metadata_global_scope',
    ArtefactMetaData.component_name,
    ArtefactMetaData.artefact_name,
    ArtefactMetaData.artefact_version,
    ArtefactMetaData.type,
    ArtefactMetaData.datasource,
    postgresql_where=ArtefactMetaData.component_version.is_(None),
)

sa.Index(
    'ix_artefact_metadata_severity',
    ArtefactMetaData.component_name,
    ArtefactMetaData.component_version,
    ArtefactMetaData.type,
    ArtefactMetaData.datasource,
    ArtefactMetaData.severity,
)

sa.Index(
    'ix_artefact_metadata_rescoring_vuln_key',
    sa.text("(data->'finding'->>'cve')"),
    sa.text("(data->'finding'->>'package_name')"),
    postgresql_where=sa.text("type = 'rescoring'"),
)

sa.Index(
    'ix_artefact_metadata_rescoring_license_key',
    sa.text("(data->'finding'->'license'->>'name')"),
    sa.text("(data->'finding'->>'package_name')"),
    postgresql_where=sa.text("type = 'rescoring'"),
)


class DBCache(Base):
    __tablename__ = 'cache'

    id = sa.Column(sa.CHAR(length=32), primary_key=True)
    descriptor = sa.Column(sa.JSON)

    creation_date = sa.Column(sa.DateTime(timezone=True), server_default=sa.sql.func.now())
    last_update = sa.Column(sa.DateTime(timezone=True), server_default=sa.sql.func.now())
    delete_after = sa.Column(sa.DateTime(timezone=True))
    keep_until = sa.Column(sa.DateTime(timezone=True))

    last_read = sa.Column(sa.DateTime(timezone=True))
    read_count = sa.Column(sa.Integer, default=0)
    revision = sa.Column(sa.Integer, default=0)
    costs = sa.Column(sa.Integer)

    size = sa.Column(sa.Integer)
    value = sa.Column(sa.LargeBinary)


class RoleBindingOriginType(enum.StrEnum):
    GITHUB = 'github'
    MANUAL = 'manual'
    OIDC = 'oidc'


@dataclasses.dataclass
class RoleBindingOrigin:
    """
    It is required to store the origin of a role binding to be able to correctly remove a binding
    again if it is not valid anymore. For example, if a user is assigned to a role XYZ because the
    user is part of a certain GitHub organisation, and the user is also manually assigned to the
    role XYZ, only the role binding which has been created because of the GitHub membership must be
    removed in case the user is not a member of the GitHub organisation anymore. The manually added
    role binding must persist.
    """

    type: RoleBindingOriginType

    @property
    def key(self) -> str:
        return self.type


@dataclasses.dataclass(kw_only=True)
class GitHubRoleBindingOrigin(RoleBindingOrigin):
    type: RoleBindingOriginType = RoleBindingOriginType.GITHUB
    hostname: str
    organisation: str | None = None
    team: str | None = None
    username: str | None = None
    app: str | None = None

    @property
    def key(self) -> str:
        return (
            f'{self.type}|{self.hostname}|{self.organisation}|{self.team}|{self.username}|{self.app}'
        )


@dataclasses.dataclass(kw_only=True)
class OidcRoleBindingOrigin(RoleBindingOrigin):
    type: RoleBindingOriginType = RoleBindingOriginType.OIDC
    issuer: str
    sub: str

    @property
    def key(self) -> str:
        return f'{self.type}|{self.issuer}|{self.sub}'


@dataclasses.dataclass
class RoleBinding:
    name: str
    origin: GitHubRoleBindingOrigin | OidcRoleBindingOrigin | RoleBindingOrigin

    @property
    def key(self) -> str:
        return f'{self.name}|{self.origin.key}'

    def __hash__(self) -> int:
        return hash(self.key)


@dataclasses.dataclass
class RefreshToken:
    identifier: uuid
    exp: unix_epoch


class User(Base):
    __tablename__ = 'users'

    id = sa.Column(sa.CHAR(length=36), primary_key=True)  # uuid
    creation_date = sa.Column(sa.DateTime(timezone=True), server_default=sa.sql.func.now())

    role_bindings = sa.Column(sa.JSON)  # list[RoleBinding]
    refresh_tokens = sa.Column(sa.JSON)  # list[RefreshToken]

    identifiers = sqlalchemy.orm.relationship('UserIdentifiers', cascade='delete')


@dataclasses.dataclass
class Identifier:
    @property
    def normalised(self) -> str:
        raise NotImplementedError

    @property
    def normalised_digest(self) -> str:
        return hashlib.sha1(
            self.normalised.encode('utf-8'),
            usedforsecurity=False,
        ).hexdigest()


@dataclasses.dataclass
class UserIdentifier(Identifier):
    username: str

    @property
    def normalised(self) -> str:
        return f'username:{self.username}'


@dataclasses.dataclass
class GitHubUserIdentifier(UserIdentifier):
    email_address: str | None
    hostname: str

    @property
    def normalised(self) -> str:
        return (
            f'username:{self.username}_email_address:{self.email_address}_hostname:{self.hostname}'
        )


@dataclasses.dataclass
class GitHubAppIdentifier(Identifier):
    app_name: str
    hostname: str

    @property
    def normalised(self) -> str:
        return f'app_name:{self.app_name}_hostname:{self.hostname}'


@dataclasses.dataclass
class OidcIdentifier(Identifier):
    sub: str
    issuer: str

    @property
    def normalised(self) -> str:
        return f'sub:{self.sub}_issuer:{self.issuer}'


class UserIdentifiers(Base):
    __tablename__ = 'user_identifiers'

    user_id = sa.Column(sa.CHAR(length=36), sa.ForeignKey('users.id'))  # uuid

    type = sa.Column(sa.String(length=32), primary_key=True)  # secret_mgmt.oauth_cfg.OAuthCfgTypes
    identifier_normalised_digest = sa.Column(sa.CHAR(length=40), primary_key=True)
    identifier = sa.Column(sa.JSON)  # Identifier

    @property
    def deserialised_identifier(
        self,
    ) -> GitHubAppIdentifier | GitHubUserIdentifier | OidcIdentifier | UserIdentifier:
        idp_type = secret_mgmt.oauth_cfg.OAuthCfgTypes(self.type)

        if idp_type is secret_mgmt.oauth_cfg.OAuthCfgTypes.GITHUB:
            if 'app_name' in self.identifier:
                data_class = GitHubAppIdentifier
            else:
                data_class = GitHubUserIdentifier

            return dacite.from_dict(
                data_class=data_class,
                data=self.identifier,
            )

        if idp_type is secret_mgmt.oauth_cfg.OAuthCfgTypes.OIDC:
            return dacite.from_dict(
                data_class=OidcIdentifier,
                data=self.identifier,
            )

        return dacite.from_dict(
            data_class=UserIdentifier,
            data=self.identifier,
        )


class BlobStore(Base):
    __tablename__: str = 'blob_store'

    digest = sa.Column(sa.String(length=256), primary_key=True)
    creation_date = sa.Column(sa.DateTime(timezone=True))
    size = sa.Column(sa.Integer)
    mime_type = sa.Column(sa.String(length=512))
    ref = sa.Column(sa.String(length=1024))
