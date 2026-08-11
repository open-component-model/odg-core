import pytest

import ocm

import responsibles.labels


def _make_component(
    labels: list[ocm.Label] = (),
    resources: list[ocm.Resource] = (),
) -> ocm.Component:
    return ocm.Component(
        name='test-component',
        version='1.0.0',
        repositoryContexts=[],
        provider='test',
        sources=[],
        componentReferences=[],
        resources=list(resources),
        labels=list(labels),
    )


def test_responsibles_label_from_dict_github_user():
    label = responsibles.labels.ResponsiblesLabel.from_dict({
        'name': 'odg.ocm.software/responsibles',
        'value': [
            {
                'type': 'githubUser',
                'username': 'octocat',
                'github_hostname': 'github.com',
            },
        ],
    })
    assert label.name == 'odg.ocm.software/responsibles'
    assert len(label.value) == 1
    responsible = label.value[0]
    assert isinstance(responsible, responsibles.labels.GitHubUserResponsible)
    assert responsible.username == 'octocat'
    assert responsible.github_hostname == 'github.com'
    assert responsible.type is responsibles.labels.ResponsibleType.GITHUB_USER


def test_responsibles_label_from_dict_github_team():
    label = responsibles.labels.ResponsiblesLabel.from_dict({
        'name': 'odg.ocm.software/responsibles',
        'value': [
            {
                'type': 'githubTeam',
                'teamname': 'org/maintainers',
            },
        ],
    })
    assert label.name == 'odg.ocm.software/responsibles'
    assert len(label.value) == 1
    responsible = label.value[0]
    assert isinstance(responsible, responsibles.labels.GitHubTeamResponsible)
    assert responsible.teamname == 'org/maintainers'
    assert responsible.type is responsibles.labels.ResponsibleType.GITHUB_TEAM


def test_responsibles_label_from_dict_email():
    label = responsibles.labels.ResponsiblesLabel.from_dict({
        'name': 'odg.ocm.software/responsibles',
        'value': [
            {
                'type': 'emailAddress',
                'email': 'dev@example.com',
            },
        ],
    })
    assert label.name == 'odg.ocm.software/responsibles'
    responsible = label.value[0]
    assert isinstance(responsible, responsibles.labels.EmailResponsible)
    assert responsible.email == 'dev@example.com'
    assert responsible.type is responsibles.labels.ResponsibleType.EMAIL


def test_responsibles_label_from_dict_multiple_responsibles():
    label = responsibles.labels.ResponsiblesLabel.from_dict({
        'name': 'odg.ocm.software/responsibles',
        'value': [
            {'type': 'githubUser', 'username': 'alice'},
            {'type': 'githubTeam', 'teamname': 'org/reviewers'},
            {'type': 'emailAddress', 'email': 'dev@example.com'},
        ],
    })
    assert len(label.value) == 3
    types = [r.type for r in label.value]
    assert responsibles.labels.ResponsibleType.GITHUB_USER in types
    assert responsibles.labels.ResponsibleType.GITHUB_TEAM in types
    assert responsibles.labels.ResponsibleType.EMAIL in types


def test_responsibles_label_legacy_name():
    label = responsibles.labels.ResponsiblesLabel.from_dict({
        'name': 'cloud.gardener.cnudie/responsibles',
        'value': [{'type': 'githubUser', 'username': 'alice'}],
    })
    assert label.name == 'cloud.gardener.cnudie/responsibles'
    responsible = label.value[0]
    assert isinstance(responsible, responsibles.labels.GitHubUserResponsible)
    assert responsible.username == 'alice'
    assert responsible.type is responsibles.labels.ResponsibleType.GITHUB_USER


# ---------------------------------------------------------------------------
# find_responsibles_label
# ---------------------------------------------------------------------------

def test_find_responsibles_label():
    label = ocm.Label(
        name='odg.ocm.software/responsibles',
        value=[{'type': 'githubUser', 'username': 'alice'}],
    )
    component = _make_component(labels=[label])
    result = responsibles.labels.find_responsibles_label(component=component)
    assert result is not None
    assert result.name == 'odg.ocm.software/responsibles'
    assert result.value[0].username == 'alice'


def test_find_responsibles_label_legacy_name():
    label = ocm.Label(
        name='cloud.gardener.cnudie/responsibles',
        value=[{'type': 'githubUser', 'username': 'alice'}],
    )
    component = _make_component(labels=[label])
    result = responsibles.labels.find_responsibles_label(component=component)
    assert result is not None
    assert result.name == 'cloud.gardener.cnudie/responsibles'
    assert result.value[0].username == 'alice'


def test_find_responsibles_label_not_found():
    component = _make_component()
    result = responsibles.labels.find_responsibles_label(component=component)
    assert result is None


def test_find_responsibles_label_artifact():
    label = ocm.Label(
        name='odg.ocm.software/responsibles',
        value=[{'type': 'githubUser', 'username': 'alice'}],
    )
    resource = ocm.Resource(
        name='test-resource', version='1.0.0', type='ociImage', access=None, labels=[label],
    )
    component = _make_component(resources=[resource])
    result = responsibles.labels.find_responsibles_label(
        component=component,
        artifact_name='test-resource',
    )
    assert result is not None
    assert result.name == 'odg.ocm.software/responsibles'
    assert result.value[0].username == 'alice'


def test_find_responsibles_label_artifact_legacy_name():
    label = ocm.Label(
        name='cloud.gardener.cnudie/responsibles',
        value=[{'type': 'githubUser', 'username': 'alice'}],
    )
    resource = ocm.Resource(
        name='test-resource', version='1.0.0', type='ociImage', access=None, labels=[label],
    )
    component = _make_component(resources=[resource])
    result = responsibles.labels.find_responsibles_label(
        component=component,
        artifact_name='test-resource',
    )
    assert result is not None
    assert result.name == 'cloud.gardener.cnudie/responsibles'
    assert result.value[0].username == 'alice'


def test_find_responsibles_label_artifact_not_found_raises():
    component = _make_component()
    with pytest.raises(ValueError):
        responsibles.labels.find_responsibles_label(
            component=component,
            artifact_name='nonexistent',
        )
