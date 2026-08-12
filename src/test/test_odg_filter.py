import odg.filter
import odg.model


def _artefact(
    component_name='github.com/org/comp',
    artefact_name='my-image',
    artefact_kind=odg.model.ArtefactKind.RESOURCE,
    artefact_type='ociImage',
) -> odg.model.ComponentArtefactId:
    return odg.model.ComponentArtefactId(
        component_name=component_name,
        component_version='1.0.0',
        artefact_kind=artefact_kind,
        artefact=odg.model.LocalArtefactId(
            artefact_name=artefact_name,
            artefact_version='1.0.0',
            artefact_type=artefact_type,
            artefact_extra_id={},
        ),
    )


def test_artefact_filter_ruleset_empty_allows_all():
    ruleset = odg.filter.ComponentArtefactRuleSet(rules=[])
    assert ruleset.allows(_artefact()) is True


def test_artefact_filter_ruleset_include_matches():
    rule = odg.filter.ComponentArtefactFilter(
        semantics=odg.filter.FilterSemantics.INCLUDE,
        name=None,
        component_name=None,
        component_version=None,
        artefact_kind=None,
        artefact_name='my-image',
        artefact_version=None,
        artefact_type=None,
        artefact_extra_id=None,
    )
    ruleset = odg.filter.ComponentArtefactRuleSet(rules=[rule])
    assert ruleset.allows(_artefact(artefact_name='my-image')) is True
    assert ruleset.allows(_artefact(artefact_name='other-image')) is False


def test_artefact_filter_ruleset_exclude_matches():
    rule = odg.filter.ComponentArtefactFilter(
        semantics=odg.filter.FilterSemantics.EXCLUDE,
        name=None,
        component_name=None,
        component_version=None,
        artefact_kind=None,
        artefact_name='skip-me',
        artefact_version=None,
        artefact_type=None,
        artefact_extra_id=None,
    )
    ruleset = odg.filter.ComponentArtefactRuleSet(rules=[rule])
    assert ruleset.allows(_artefact(artefact_name='keep-me')) is True
    assert ruleset.allows(_artefact(artefact_name='skip-me')) is False


def test_artefact_filter_ruleset_include_and_exclude():
    include = odg.filter.ComponentArtefactFilter(
        semantics=odg.filter.FilterSemantics.INCLUDE,
        name=None,
        component_name='github.com/org/.*',
        component_version=None,
        artefact_kind=None,
        artefact_name=None,
        artefact_version=None,
        artefact_type=None,
        artefact_extra_id=None,
    )
    exclude = odg.filter.ComponentArtefactFilter(
        semantics=odg.filter.FilterSemantics.EXCLUDE,
        name=None,
        component_name=None,
        component_version=None,
        artefact_kind=None,
        artefact_name='skip-me',
        artefact_version=None,
        artefact_type=None,
        artefact_extra_id=None,
    )
    ruleset = odg.filter.ComponentArtefactRuleSet(rules=[include, exclude])
    # included component, not excluded artefact → allowed
    assert ruleset.allows(_artefact(artefact_name='keep-me')) is True
    # included component, but excluded artefact → denied
    assert ruleset.allows(_artefact(artefact_name='skip-me')) is False
    # component outside include pattern → denied
    assert (
        ruleset.allows(
            _artefact(
                component_name='github.com/other/comp',
                artefact_name='keep-me',
            ),
        )
        is False
    )
