import responsibles.labels


def test_responsibles_label_from_dict_github_user():
    label = responsibles.labels.ResponsiblesLabel.from_dict(
        {
            'name': 'cloud.gardener.cnudie/responsibles',
            'value': [
                {
                    'type': 'githubUser',
                    'username': 'octocat',
                    'github_hostname': 'github.com',
                },
            ],
        },
    )
    assert len(label.value) == 1
    responsible = label.value[0]
    assert isinstance(responsible, responsibles.labels.GitHubUserResponsible)
    assert responsible.username == 'octocat'
    assert responsible.github_hostname == 'github.com'
    assert responsible.type is responsibles.labels.ResponsibleType.GITHUB_USER


def test_responsibles_label_from_dict_github_team():
    label = responsibles.labels.ResponsiblesLabel.from_dict(
        {
            'name': 'cloud.gardener.cnudie/responsibles',
            'value': [
                {
                    'type': 'githubTeam',
                    'teamname': 'org/maintainers',
                },
            ],
        },
    )
    assert len(label.value) == 1
    responsible = label.value[0]
    assert isinstance(responsible, responsibles.labels.GitHubTeamResponsible)
    assert responsible.teamname == 'org/maintainers'
    assert responsible.type is responsibles.labels.ResponsibleType.GITHUB_TEAM


def test_responsibles_label_from_dict_email():
    label = responsibles.labels.ResponsiblesLabel.from_dict(
        {
            'name': 'cloud.gardener.cnudie/responsibles',
            'value': [
                {
                    'type': 'emailAddress',
                    'email': 'dev@example.com',
                },
            ],
        },
    )
    responsible = label.value[0]
    assert isinstance(responsible, responsibles.labels.EmailResponsible)
    assert responsible.email == 'dev@example.com'
    assert responsible.type is responsibles.labels.ResponsibleType.EMAIL


def test_responsibles_label_from_dict_multiple_responsibles():
    label = responsibles.labels.ResponsiblesLabel.from_dict(
        {
            'name': 'cloud.gardener.cnudie/responsibles',
            'value': [
                {'type': 'githubUser', 'username': 'alice'},
                {'type': 'githubTeam', 'teamname': 'org/reviewers'},
                {'type': 'emailAddress', 'email': 'dev@example.com'},
            ],
        },
    )
    assert len(label.value) == 3
    types = [r.type for r in label.value]
    assert responsibles.labels.ResponsibleType.GITHUB_USER in types
    assert responsibles.labels.ResponsibleType.GITHUB_TEAM in types
    assert responsibles.labels.ResponsibleType.EMAIL in types


def test_responsibles_label_name():
    label = responsibles.labels.ResponsiblesLabel.from_dict(
        {
            'name': 'cloud.gardener.cnudie/responsibles',
            'value': [{'type': 'githubUser', 'username': 'alice'}],
        },
    )
    assert label.name == 'cloud.gardener.cnudie/responsibles'
