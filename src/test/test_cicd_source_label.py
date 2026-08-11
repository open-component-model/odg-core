import ocm

import components


def _make_source(name: str, with_cicd_label: bool) -> ocm.Source:
    labels = []
    if with_cicd_label:
        labels.append(ocm.Label(
            name='cloud.gardener/cicd/source',
            value={'repository-classification': 'main'},
        ))
    return ocm.Source(
        name=name,
        access={'type': 'github', 'repoUrl': 'github.com/example/repo'},
        labels=labels,
    )


def test_cicd_source_label_added_to_first_source_when_missing():
    sources = [_make_source('main', with_cicd_label=False)]
    components._ensure_cicd_source_label(sources)
    label_names = [label.name for label in sources[0].labels]
    assert 'cloud.gardener/cicd/source' in label_names
    assert next(
        l for l in sources[0].labels if l.name == 'cloud.gardener/cicd/source'
    ).value == {'repository-classification': 'main'}


def test_cicd_source_label_not_added_when_already_present_on_first_source():
    sources = [_make_source('main', with_cicd_label=True)]
    original_count = len(sources[0].labels)
    components._ensure_cicd_source_label(sources)
    assert len(sources[0].labels) == original_count


def test_cicd_source_label_not_added_when_present_on_second_source():
    sources = [
        _make_source('main', with_cicd_label=False),
        _make_source('secondary', with_cicd_label=True),
    ]
    original_first_count = len(sources[0].labels)
    components._ensure_cicd_source_label(sources)
    assert len(sources[0].labels) == original_first_count


def test_cicd_source_label_added_to_first_source_only_when_multiple_sources_missing():
    sources = [
        _make_source('main', with_cicd_label=False),
        _make_source('secondary', with_cicd_label=False),
    ]
    components._ensure_cicd_source_label(sources)
    first_label_names = [l.name for l in sources[0].labels]
    second_label_names = [l.name for l in sources[1].labels]
    assert 'cloud.gardener/cicd/source' in first_label_names
    assert 'cloud.gardener/cicd/source' not in second_label_names


def test_cicd_source_label_no_op_when_no_sources():
    sources = []
    components._ensure_cicd_source_label(sources)
    assert sources == []
