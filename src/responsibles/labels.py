import dataclasses
import enum

import dacite

import ocm


class ResponsibleType(enum.Enum):
    GITHUB_USER = 'githubUser'
    GITHUB_TEAM = 'githubTeam'
    CODEOWNERS = 'codeowners'
    EMAIL = 'emailAddress'
    PERSONAL_NAME = 'personalName'


@dataclasses.dataclass(frozen=True, kw_only=True)
class Responsible:
    # Not intended to be instantiated
    type: ResponsibleType


@dataclasses.dataclass(frozen=True, kw_only=True)
class GitHubUserResponsible(Responsible):
    username: str
    github_hostname: str = None
    type: ResponsibleType = ResponsibleType.GITHUB_USER


@dataclasses.dataclass(frozen=True, kw_only=True)
class GitHubTeamResponsible(Responsible):
    teamname: str
    github_hostname: str = None
    type: ResponsibleType = ResponsibleType.GITHUB_TEAM


@dataclasses.dataclass(frozen=True, kw_only=True)
class CodeownersResponsible(Responsible):
    type: ResponsibleType = ResponsibleType.CODEOWNERS


@dataclasses.dataclass(frozen=True, kw_only=True)
class EmailResponsible(Responsible):
    email: str
    type: ResponsibleType = ResponsibleType.EMAIL


@dataclasses.dataclass(frozen=True, kw_only=True)
class PersonalNameResponsible(Responsible):
    firstName: str
    lastName: str
    type: ResponsibleType = ResponsibleType.PERSONAL_NAME


@dataclasses.dataclass(frozen=True, kw_only=True)
class ResponsiblesLabel(ocm.Label):
    value: list[
        CodeownersResponsible
        | EmailResponsible
        | GitHubTeamResponsible
        | GitHubUserResponsible
        | PersonalNameResponsible
    ]
    name: str = 'odg.ocm.software/responsibles'

    @staticmethod
    def from_dict(data_dict: dict):
        return dacite.from_dict(
            data_class=ResponsiblesLabel,
            data=data_dict,
            config=dacite.Config(
                cast=[
                    ResponsibleType,
                ],
                strict=True,
            ),
        )


def find_responsibles_label(
    component: ocm.Component,
    artifact_name: str | None = None,
) -> 'ResponsiblesLabel | None':
    """
    Returns the most specific ResponsiblesLabel for the given component and artifact name,
    or None if no label is found.

    Raises ValueError if artifact_name is given but no matching artifact exists.
    """
    label_names = [ResponsiblesLabel.name, 'cloud.gardener.cnudie/responsibles']  # legacy alias

    if artifact_name:
        matching_artifacts = [
            a for a in component.resources + component.sources if a.name == artifact_name
        ]
        if not matching_artifacts:
            raise ValueError(
                f'{component.name}:{component.version} has no artifact {artifact_name!r}',
            )

        for artifact in matching_artifacts:
            for name in label_names:
                if raw := artifact.find_label(name=name):
                    return ResponsiblesLabel.from_dict(
                        data_dict=dataclasses.asdict(raw),
                    )

    for name in label_names:
        if raw := component.find_label(name=name):
            return ResponsiblesLabel.from_dict(
                data_dict=dataclasses.asdict(raw),
            )

    return None
