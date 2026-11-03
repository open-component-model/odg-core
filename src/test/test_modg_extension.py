import enum
import os

import dacite
import jsonpath_ng
import pytest
import yaml


import odg_operator.__main__ as odgc
import odg_operator.odg_model as odgm
import odg_operator.odg_util as odgu


_own_dir = os.path.abspath(os.path.dirname(__file__))
test_resources_extension_definitions = os.path.join(
    _own_dir,
    'resources/extension-definitions.yaml',
)


@pytest.fixture()
def extension_definitions():
    with open(test_resources_extension_definitions, 'r') as f:
        return list(yaml.safe_load_all(f))


def test_jsonpatch_patch():
    assert {'foo': {'bar': {'foo.bar': 42}}} == odgu.patch_jsonpath_into_dict(
        'foo.bar."foo.bar"',
        42,
    )  # noqa: E501


def test_extensions(extension_definitions):
    ds, dd, db, sb = [
        dacite.from_dict(
            data=raw,
            data_class=odgm.ExtensionDefinition,
            config=dacite.Config(
                cast=[enum.Enum],
            ),
        )
        for raw in extension_definitions
    ]

    missing = set(
        odgc.iter_missing_dependencies(
            requested=(dd,),
            known=(ds, dd, db, sb),
        ),
    )
    assert missing == set([ds, db])

    context = {
        'base_url': 'my-domain.com',
        'target_namespace': 'my-target-namespace',
    }

    outputs = dict(
        [
            (extension_definition.name, extension_definition.templated_outputs(context))
            for extension_definition in (dd, ds, db)
        ],
    )

    ds_outputs = outputs['delivery-service']
    assert ds_outputs[0].name == 'delivery-service-url'
    assert ds_outputs[0].value == 'https://delivery-service.my-domain.com'

    outputs = odgc.outputs_as_jsonpath(outputs)
    path = jsonpath_ng.parse('dependencies.delivery-service.outputs.delivery-service-url')
    assert path.find(outputs)[0].value == 'https://delivery-service.my-domain.com'

    patched_values = [
        odgu.template_and_resolve_jsonpath(
            value=value_template.value,
            jsonpaths=outputs,
            substitution_context=context,
            value_type=value_template.value_type,
        )
        for value_template in dd.installation.value_templates
    ]
    assert patched_values[0] == 'my-target-namespace'
    assert patched_values[1] == ['delivery-dashboard.my-domain.com']
    assert patched_values[2] == 'https://delivery-service.my-domain.com'

    assert odgu.template_and_resolve_jsonpath(
        value={'foo': 'bar.${base_url}'},
        jsonpaths=outputs,
        substitution_context=context,
        value_type=odgm.ValueType.PYTHON_STRING_TEMPLATE,
    ) == {
        'foo': 'bar.my-domain.com',
    }

    with pytest.raises(KeyError):
        odgu.template_and_resolve_jsonpath(
            value={'foo': 'bar.${base_url}'},
            jsonpaths=outputs,
            substitution_context={},
            value_type=odgm.ValueType.PYTHON_STRING_TEMPLATE,
            default_value=None,
        )

    assert odgu.template_and_resolve_jsonpath(
        value={'foo': 'bar.${base_url}'},
        jsonpaths=outputs,
        substitution_context={},
        value_type=odgm.ValueType.PYTHON_STRING_TEMPLATE,
        default_value='bar.default-domain.com',
    ) == {
        'foo': 'bar.default-domain.com',
    }

    # value_type=boolean yields real bools regardless of source representation,
    # so helm chart conditions and boolean-typed schema fields validate.
    for src, expected in (
        (True, True),
        (False, False),
        ('True', True),
        ('False', False),
        ('true', True),
        ('false', False),
        ('1', True),
        ('0', False),
        ('yes', True),
        ('no', False),
        ('on', True),
        ('off', False),
        ('', False),
    ):
        assert (
            odgu.template_and_resolve_jsonpath(
                value='${flag}',
                jsonpaths={},
                substitution_context={'flag': src},
                value_type=odgm.ValueType.BOOLEAN,
            )
            is expected
        ), (src, expected)

    # unparseable values raise so misconfigurations are loud, not silently truthy/falsy
    with pytest.raises(ValueError):
        odgu.template_and_resolve_jsonpath(
            value='${flag}',
            jsonpaths={},
            substitution_context={'flag': 'maybe'},
            value_type=odgm.ValueType.BOOLEAN,
        )

    # non-boolean strings pass through untouched
    assert (
        odgu.template_and_resolve_jsonpath(
            value='${host}',
            jsonpaths={},
            substitution_context={'host': 'my-domain.com'},
            value_type=odgm.ValueType.PYTHON_STRING_TEMPLATE,
        )
        == 'my-domain.com'
    )

    missing = set(
        odgc.iter_missing_dependencies(
            requested=(sb,),
            known=(ds, dd, db, sb),
        ),
    )
    assert missing == {ds, db}

    assert sb.templated_outputs(context) == []

    patched_values = [
        odgu.template_and_resolve_jsonpath(
            value=value_template.value,
            jsonpaths=outputs,
            substitution_context=context,
            value_type=value_template.value_type,
        )
        for value_template in sb.installation.value_templates
    ]
    assert patched_values[0] == 'my-target-namespace'
    assert patched_values[1] is True


def test_default_namespace():
    namespaced = {'kind': 'ServiceAccount', 'metadata': {'name': 'foo'}}
    assert odgc._default_namespace(namespaced, 'bar')['metadata']['namespace'] == 'bar'

    explicit = {'kind': 'Deployment', 'metadata': {'name': 'foo', 'namespace': 'baz'}}
    assert odgc._default_namespace(explicit, 'bar')['metadata']['namespace'] == 'baz'

    for kind in ('ClusterRole', 'ClusterRoleBinding', 'CustomResourceDefinition'):
        cluster_scoped = {'kind': kind, 'metadata': {'name': 'foo'}}
        assert 'namespace' not in odgc._default_namespace(cluster_scoped, 'bar')['metadata']
